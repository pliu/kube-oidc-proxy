// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

func TestCancellationClosesBlockedLDAPWrite(t *testing.T) {
	for _, stage := range []string{"bind", "search", "starttls"} {
		for _, cause := range []string{"cancel", "timeout"} {
			t.Run(stage+"/"+cause, func(t *testing.T) {
				client, server := net.Pipe()
				defer server.Close()
				ldapConn := goldap.NewConn(client, false)
				ldapConn.Start()
				c := &socketConn{Conn: ldapConn, socket: client}
				defer c.Close()
				config := testConfig()
				config.Backends[0].URLs = []string{"ldap://ldap.example.net:389"}
				config.Backends[0].StartTLS = stage == "starttls"
				if stage == "search" {
					config.Backends[0].BindDN = ""
					config.Backends[0].BindPassword = ""
				}
				config.Backends[0].Timeout = NewDuration(time.Second)
				d := newTestResolver(t, config, c)
				ctx, cancel := context.WithCancel(context.Background())
				expected := context.Canceled
				if cause == "timeout" {
					ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
					expected = context.DeadlineExceeded
				}
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := d.searchUser(ctx, "alice", false); done <- err }()
				// Read one byte so a real request is being written, then stop
				// reading to model a peer with a full receive window.
				server.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := server.Read(make([]byte, 1)); err != nil {
					t.Fatal(err)
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
					// Release the write before cleanup if the regression returns.
					server.Close()
					t.Fatal("cancellation did not interrupt blocked write")
				}
			})
		}
	}
}

func newPipeConn(t *testing.T) (*socketConn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { server.Close() })
	ldapConn := goldap.NewConn(client, false)
	ldapConn.Start()
	c := &socketConn{Conn: ldapConn, socket: client}
	t.Cleanup(func() { c.Close() })
	return c, server
}

func TestRetireUnbindsBeforeClosing(t *testing.T) {
	c, server := newPipeConn(t)
	done := make(chan struct{})
	go func() { c.retire(); close(done) }()

	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	packet, err := ber.ReadPacket(server)
	if err != nil {
		t.Fatalf("expected an unbind request, got %v", err)
	}
	if len(packet.Children) < 2 || packet.Children[1].Tag != goldap.ApplicationUnbindRequest {
		t.Fatalf("expected an unbind request, got %s", goldap.ApplicationMap[uint8(packet.Children[1].Tag)])
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retire did not return after unbinding")
	}
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("expected the connection to be closed after the unbind, got %v", err)
	}
	if !c.IsClosing() {
		t.Error("expected the retired connection to be closing")
	}
}

func TestRetireGivesUpOnPeerThatStoppedReading(t *testing.T) {
	defer func(timeout time.Duration) { retireTimeout = timeout }(retireTimeout)
	retireTimeout = 50 * time.Millisecond

	c, _ := newPipeConn(t)
	done := make(chan struct{})
	go func() { c.retire(); close(done) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retire blocked on a peer that is not reading")
	}
}

func TestDialLDAPSVerifiesCertificates(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, tc := range []struct {
		name    string
		config  *tls.Config
		wantErr bool
	}{
		{"trusted", &tls.Config{RootCAs: roots}, false},
		{"untrusted", &tls.Config{}, true},
		{"wrong hostname", &tls.Config{RootCAs: roots, ServerName: "wrong.example.net"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &backend{config: testConfig().Backends[0], tlsConfig: tc.config}
			b.config.Timeout = NewDuration(time.Second)
			c, err := b.dialLDAP(strings.Replace(server.URL, "https://", "ldaps://", 1))
			if c != nil {
				defer c.Close()
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected dial result: %v", err)
			}
		})
	}
}

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
				go func() { _, err := d.searchUser(ctx, "alice", false); done <- err }()
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
	go func() { _, err := d.searchUser(ctx, "alice", false); done <- err }()
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
