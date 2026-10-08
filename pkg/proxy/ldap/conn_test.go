// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// stalledConn models LDAP calls that only unblock when their connection closes.
type stalledConn struct {
	*fakeConn
	stage   string
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
	closes  atomic.Int64
}

func newStalledConn(stage string) *stalledConn {
	return &stalledConn{fakeConn: &fakeConn{}, stage: stage, entered: make(chan struct{}), closed: make(chan struct{})}
}
func (c *stalledConn) wait(stage string) error {
	if c.stage != stage {
		return nil
	}
	close(c.entered)
	<-c.closed
	return errors.New("connection closed")
}
func (c *stalledConn) StartTLS(config *tls.Config) error {
	if err := c.wait("starttls"); err != nil {
		return err
	}
	return c.fakeConn.StartTLS(config)
}
func (c *stalledConn) Bind(username, password string) error {
	if err := c.wait("bind"); err != nil {
		return err
	}
	return c.fakeConn.Bind(username, password)
}
func (c *stalledConn) Search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	if err := c.wait("search"); err != nil {
		return nil, err
	}
	return c.fakeConn.Search(req)
}
func (c *stalledConn) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestContextClosesBlockedLDAPOperations(t *testing.T) {
	for _, stage := range []string{"starttls", "bind", "search"} {
		for _, cause := range []string{"cancel", "timeout"} {
			t.Run(stage+"/"+cause, func(t *testing.T) {
				config := testConfig()
				config.Backends[0].URLs = []string{"ldap://ldap.example.net:389"}
				config.Backends[0].StartTLS = stage == "starttls"
				config.Backends[0].Timeout = NewDuration(time.Hour)
				expected := context.Canceled
				if cause == "timeout" {
					config.Backends[0].Timeout = NewDuration(20 * time.Millisecond)
					expected = context.DeadlineExceeded
				}
				c := newStalledConn(stage)
				d := newTestResolver(t, config, c)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := d.searchUser(ctx, "alice"); done <- err }()
				select {
				case <-c.entered:
				case <-time.After(time.Second):
					t.Fatal("LDAP operation did not start")
				}
				if cause == "cancel" {
					cancel()
				}
				select {
				case err := <-done:
					if !errors.Is(err, expected) {
						t.Fatalf("expected %v, got %v", expected, err)
					}
				case <-time.After(time.Second):
					t.Fatal("context did not unblock LDAP")
				}
				if c.closes.Load() != 1 {
					t.Fatalf("connection closed %d times", c.closes.Load())
				}
			})
		}
	}
}

func TestLateDialConnectionIsClosedWithoutBinding(t *testing.T) {
	c := newStalledConn("bind")
	d := newTestResolver(t, testConfig(), c)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	d.backends[0].dial = func(string) (conn, error) { close(entered); <-release; return c, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := d.searchUser(ctx, "alice"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled dial did not return")
	}
	unblock()
	select {
	case <-c.closed:
	case <-time.After(time.Second):
		t.Fatal("late connection leaked")
	}
	select {
	case <-c.entered:
		t.Fatal("late connection was bound")
	default:
	}
	if c.closes.Load() != 1 {
		t.Fatalf("late connection closed %d times", c.closes.Load())
	}
}

func TestHandshakeFailureClosesBeforeFailover(t *testing.T) {
	for _, stage := range []string{"starttls", "bind"} {
		t.Run(stage, func(t *testing.T) {
			config := testConfig()
			config.Backends[0].URLs = []string{"ldap://bad.example.net:389", "ldap://good.example.net:389"}
			config.Backends[0].StartTLS = stage == "starttls"
			first, second := newStalledConn(""), newStalledConn("")
			if stage == "starttls" {
				first.startTLSErr = errors.New("bad TLS")
			} else {
				first.bindErr = errors.New("bad bind")
			}
			d := newTestResolver(t, config, first)
			d.backends[0].dial = func(url string) (conn, error) {
				if url == config.Backends[0].URLs[0] {
					return first, nil
				}
				select {
				case <-first.closed:
				default:
					t.Error("failed connection remained open during failover")
				}
				return second, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := d.backends[0].withConn(ctx, func(c conn) error {
				if c != second {
					t.Error("wrong failover connection")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			cancel()
			if first.closes.Load() != 1 || second.closes.Load() != 1 {
				t.Fatalf("close counts: failed=%d successful=%d", first.closes.Load(), second.closes.Load())
			}
		})
	}
}
