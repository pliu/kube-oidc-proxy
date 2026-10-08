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
)

func TestResolvePersistsAndCacheHitDoesNoIO(t *testing.T) {
	d, client := userTestDirectory(t)
	var calls atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) {
		calls.Add(1)
		return connWithUsers([]string{"Developers"}, map[string][]string{"alice": {"Developers"}}), nil
	}
	groups, found, err := d.Resolve(context.Background(), "ALICE")
	if err != nil || !found || !reflect.DeepEqual(groups, []string{"Developers"}) {
		t.Fatalf("%v %v %v", groups, found, err)
	}
	saved, err := d.store.Get(context.Background(), "alice")
	if err != nil || !reflect.DeepEqual(saved.Record.Groups, groups) {
		t.Fatalf("%+v %v", saved, err)
	}
	count := len(client.Actions())
	groups[0] = "mutated"
	again, _, err := d.Resolve(context.Background(), "alice")
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
	go func() { _, _, err := d.Resolve(ctx, "alice"); first <- err }()
	<-entered
	const waiters = 12
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := d.Resolve(context.Background(), "alice"); err != nil {
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
		go func() { _, _, err := d.Resolve(context.Background(), name); result <- err }()
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
	if d.Stats().Users != 0 {
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
	go func() { _, err := d.RefreshUser(ctx, "alice"); refresh <- err }()
	<-entered
	miss := make(chan error, 1)
	go func() { _, _, err := d.Resolve(context.Background(), "alice"); miss <- err }()
	cancel()
	if err := <-refresh; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if err := <-miss; err != nil {
		t.Fatalf("refresh waiter canceled shared work: %v", err)
	}
}
