// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
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
	if d.isLeader() {
		t.Fatal("directory assumed leadership before an elector was configured")
	}
	d.resolver.config.RefreshInterval = NewDuration(10 * time.Millisecond)
	var calls atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) { calls.Add(1); return connWithUsers(nil, nil), nil }
	if _, _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	var leading atomic.Bool
	d.SetLeaderCheck(leading.Load)
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
	leading.Store(false)
}
