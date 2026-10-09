// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveRequeriesAfterDirectoryOrBindIdentityChange(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"directory URL": func(c *Config) { c.Backends[0].URLs = []string{"ldaps://replacement.example.net"} },
		"bind identity": func(c *Config) { c.Backends[0].BindDN = "CN=Other,DC=example,DC=net" },
	} {
		t.Run(name, func(t *testing.T) {
			previous, client := userTestDirectory(t)
			previous.resolver.backends[0].dial = func(string) (conn, error) {
				return connWithUsers([]string{"Old"}, map[string][]string{"alice": {"Old"}}), nil
			}
			if _, err := previous.Resolve(context.Background(), "alice"); err != nil {
				t.Fatal(err)
			}

			config := testConfig()
			change(config)
			store, err := cache.NewConfigMaps(client, "proxy", config.UserRecordFingerprint())
			if err != nil {
				t.Fatal(err)
			}
			directory, err := NewUserDirectory(config, store, previous.leadership)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(directory.cancel)
			calls := 0
			directory.resolver.backends[0].dial = func(string) (conn, error) {
				calls++
				return connWithUsers([]string{"New"}, map[string][]string{"alice": {"New"}}), nil
			}
			if _, err := directory.restoreUsers(context.Background()); err != nil {
				t.Fatal(err)
			}
			groups, err := directory.Resolve(context.Background(), "alice")
			if err != nil || calls != 1 || !reflect.DeepEqual(groups, []string{"New"}) {
				t.Fatalf("old memberships reused: groups=%v calls=%d err=%v", groups, calls, err)
			}
			saved, err := store.Get(context.Background(), "alice")
			if err != nil || saved.Invalid != nil || saved.Record == nil || !reflect.DeepEqual(saved.Record.Groups, groups) {
				t.Fatalf("replacement memberships not persisted: entry=%+v err=%v", saved, err)
			}
		})
	}
}

func TestResolveKeepsRawUsernamePrefixDistinct(t *testing.T) {
	config := testConfig()
	config.UsernamePrefix = "oidc:"
	config.SetDefaults()
	store, err := cache.NewConfigMaps(fake.NewClientset(), "proxy", config.UserRecordFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewUserDirectory(config, store, func() context.Context { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.cancel)
	var calls atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) {
		calls.Add(1)
		return connWithUsers([]string{"PrefixedIdentity", "PlainIdentity"}, map[string][]string{
			"oidc:alice": {"PrefixedIdentity"},
			"alice":      {"PlainIdentity"},
		}), nil
	}
	identities := []struct{ request, canonical, group string }{
		{"oidc:oidc:Alice", "oidc:alice", "PrefixedIdentity"},
		{"oidc:Alice", "alice", "PlainIdentity"},
	}
	check := func(directory *UserDirectory) {
		t.Helper()
		for _, identity := range identities {
			groups, err := directory.Resolve(context.Background(), identity.request)
			if err != nil || !reflect.DeepEqual(groups, []string{identity.group}) {
				t.Fatalf("resolve %q: groups=%v err=%v", identity.request, groups, err)
			}
			saved, err := store.Get(context.Background(), identity.canonical)
			if err != nil || saved.Record == nil || saved.Record.Username != identity.canonical || !reflect.DeepEqual(saved.Record.Groups, groups) {
				t.Fatalf("persisted %q: entry=%+v err=%v", identity.canonical, saved, err)
			}
		}
	}
	check(d)
	check(d)
	if calls.Load() != 2 {
		t.Fatalf("cache hits queried LDAP: %d lookups", calls.Load())
	}
	if err := d.RefreshCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	check(d)
	// A fresh replica must restore the same distinct identities without LDAP.
	restored, err := NewUserDirectory(config, store, func() context.Context { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.cancel)
	restored.resolver.backends[0].dial = func(string) (conn, error) {
		t.Error("restored record queried LDAP")
		return nil, errors.New("unexpected LDAP lookup")
	}
	if _, err := restored.restoreUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	check(restored)
}

func TestResolvePersistsAndCacheHitDoesNoIO(t *testing.T) {
	d, client := userTestDirectory(t)
	var calls atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) {
		calls.Add(1)
		return connWithUsers([]string{"Developers"}, map[string][]string{"alice": {"Developers"}}), nil
	}
	groups, err := d.Resolve(context.Background(), "ALICE")
	if err != nil || !reflect.DeepEqual(groups, []string{"Developers"}) {
		t.Fatalf("%v %v", groups, err)
	}
	saved, err := d.store.Get(context.Background(), "alice")
	if err != nil || !reflect.DeepEqual(saved.Record.Groups, groups) {
		t.Fatalf("%+v %v", saved, err)
	}
	count := len(client.Actions())
	groups[0] = "mutated"
	again, err := d.Resolve(context.Background(), "alice")
	if err != nil || calls.Load() != 1 || len(client.Actions()) != count || again[0] != "Developers" {
		t.Fatalf("cache hit performed I/O or mutated: %v %v", again, err)
	}
}

func TestResolveCoalescesAndCanceledWaiterDoesNotCancelOthers(t *testing.T) {
	d, _ := userTestDirectory(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return connWithUsers(nil, map[string][]string{"alice": {}}), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := d.Resolve(ctx, "alice"); first <- err }()
	<-entered
	const waiters = 12
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.Resolve(context.Background(), "alice"); err != nil {
				t.Error(err)
			}
		}()
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("%d lookups", calls.Load())
	}
}

func TestResolveIndependentUsersAndBackendFailure(t *testing.T) {
	d, _ := userTestDirectory(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	d.resolver.backends[0].dial = func(string) (conn, error) {
		entered <- struct{}{}
		<-release
		return nil, errors.New("LDAP unavailable")
	}
	result := make(chan error, 2)
	for _, name := range []string{"alice", "bob"} {
		go func() { _, err := d.Resolve(context.Background(), name); result <- err }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("independent users blocked each other")
		}
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-result; err == nil {
			t.Fatal("partial result succeeded")
		}
	}
	if _, ok := d.cached("alice"); ok {
		t.Fatal("failed lookup was cached")
	}
}

func TestCanceledRefreshWaiterDoesNotCancelSharedMiss(t *testing.T) {
	d, _ := userTestDirectory(t)
	entered, release := make(chan struct{}), make(chan struct{})
	d.resolver.backends[0].dial = func(string) (conn, error) {
		close(entered)
		<-release
		return connWithUsers(nil, map[string][]string{"alice": {}}), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	refresh := make(chan error, 1)
	go func() { _, err := d.resolve(ctx, "alice", true); refresh <- err }()
	<-entered
	miss := make(chan error, 1)
	go func() { _, err := d.Resolve(context.Background(), "alice"); miss <- err }()
	cancel()
	if err := <-refresh; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if err := <-miss; err != nil {
		t.Fatalf("refresh waiter canceled shared work: %v", err)
	}
}

func TestCollidingNamesNeverShareGroups(t *testing.T) {
	d, _ := userTestDirectory(t)
	d.resolver.backends[0].dial = func(string) (conn, error) {
		return connWithUsers([]string{"AtGroup", "DashGroup"}, map[string][]string{
			"alice@example.net": {"AtGroup"},
			"alice-example.net": {"DashGroup"},
		}), nil
	}
	want := map[string]string{"alice@example.net": "AtGroup", "alice-example.net": "DashGroup"}
	// Alternate so each lookup finds the other user's record under the shared name.
	for i := 0; i < 3; i++ {
		for _, username := range []string{"alice@example.net", "alice-example.net"} {
			groups, err := d.Resolve(context.Background(), username)
			if err != nil || len(groups) != 1 || groups[0] != want[username] {
				t.Fatalf("%s got %v %v, want [%s]", username, groups, err, want[username])
			}
		}
	}
}
