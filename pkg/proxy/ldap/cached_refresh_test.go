// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshOnlyCachedUsersIncludingAbsent(t *testing.T) {
	d, _ := userTestDirectory(t)
	var calls atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) {
		calls.Add(1)
		return connWithUsers([]string{"Old"}, map[string][]string{"alice": {"Old"}, "uncached": {"Old"}}), nil
	}
	if _, _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.Resolve(context.Background(), "absent"); err != nil || found {
		t.Fatalf("%t %v", found, err)
	}
	before := calls.Load()
	d.resolver.backends[0].dial = func(string) (conn, error) {
		calls.Add(1)
		return connWithUsers([]string{"New"}, map[string][]string{"absent": {"New"}, "uncached": {"New"}}), nil
	}
	if err := d.RefreshCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load()-before != 2 {
		t.Fatal("refresh did not search exactly the two cached users")
	}
	alice, ok := d.cached("alice")
	if !ok || alice.Record.Found || len(alice.Record.Groups) != 0 {
		t.Fatal("absent user retained old grants")
	}
	absent, ok := d.cached("absent")
	if !ok || !absent.Record.Found || absent.Record.Groups[0] != "New" {
		t.Fatal("newly provisioned user was not refreshed")
	}
	if _, ok := d.cached("uncached"); ok {
		t.Fatal("refresh enumerated uncached user")
	}
}

func TestPeriodicRefreshRequiresLeadership(t *testing.T) {
	d, _ := userTestDirectory(t)
	d.resolver.config.RefreshInterval = NewDuration(10 * time.Millisecond)
	var calls atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) { calls.Add(1); return connWithUsers(nil, nil), nil }
	if _, _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	var leading atomic.Bool
	term, cancelTerm := context.WithCancel(context.Background())
	defer cancelTerm()
	d.leadership = func() context.Context {
		if leading.Load() {
			return term
		}
		return nil
	}
	go d.runRefresh()
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("follower refreshed")
	}
	leading.Store(true)
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() == 1 {
		t.Fatal("leader never refreshed")
	}
	cancelTerm()
}

func TestLeadershipLossStopsRefreshWithoutCancelingSharedLookup(t *testing.T) {
	d, _ := userTestDirectory(t)
	d.resolver.config.LookupConcurrency = 1
	d.apply(userTestEntry(t, d, "1", "Old"), false)
	term, cancelTerm := context.WithCancel(context.Background())
	defer cancelTerm()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	d.resolver.backends[0].dial = func(string) (conn, error) {
		close(entered)
		<-release
		return connWithUsers([]string{"New"}, map[string][]string{"alice": {"New"}}), nil
	}
	cycleDone := make(chan error, 1)
	go func() { cycleDone <- d.refreshWhileLeader(term) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh never started")
	}
	cancelTerm()
	select {
	case err := <-cycleDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leadership loss returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh waited for LDAP after leadership loss")
	}
	// Work admitted by the old term must remain alive and finish its commit.
	d.callsMu.Lock()
	call := d.calls["alice"]
	d.callsMu.Unlock()
	if call == nil {
		t.Fatal("leadership loss canceled shared work")
	}
	unblock()
	select {
	case <-call.done:
		if call.err != nil {
			t.Fatalf("shared lookup was canceled: %v", call.err)
		}
	case <-time.After(time.Second):
		t.Fatal("shared lookup never completed")
	}

	groups, found, err := d.Resolve(context.Background(), "alice")
	if err != nil || !found || len(groups) != 1 || groups[0] != "New" {
		t.Fatalf("shared result lost: %v %t %v", groups, found, err)
	}
}

func TestReplicaShutdownCancelsRefreshWait(t *testing.T) {
	d, _ := userTestDirectory(t)
	d.apply(userTestEntry(t, d, "1000", "Old"), false)
	entered := make(chan struct{})
	d.resolver.backends[0].dial = func(string) (conn, error) {
		close(entered)
		<-d.ctx.Done()
		return nil, d.ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- d.refreshWhileLeader(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh never started")
	}
	d.cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not stop refresh waiting")
	}
}
