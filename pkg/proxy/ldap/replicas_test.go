// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
)

func TestReplicasRaceOnMissAndRefreshWithDelayedWatches(t *testing.T) {
	first, _ := userTestDirectory(t)
	second := newTestReplica(t, first)
	// No watch is started: each replica must remain correct with arbitrarily
	// delayed events, using only resource versions returned by the API.
	for _, refresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "miss", true: "refresh"}[refresh], func(t *testing.T) {
			entered := make(chan struct{}, 2)
			releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
			first.resolver.backends[0].dial = func(string) (conn, error) {
				entered <- struct{}{}
				<-releaseFirst
				return connWithUsers([]string{"Winner"}, map[string][]string{"alice": {"Winner"}}), nil
			}
			second.resolver.backends[0].dial = func(string) (conn, error) {
				entered <- struct{}{}
				<-releaseSecond
				return connWithUsers([]string{"Stale"}, map[string][]string{"alice": {"Stale"}}), nil
			}
			// Force refresh to change memberships, even in the winning replica.
			if refresh {
				first.resolver.backends[0].dial = func(string) (conn, error) {
					entered <- struct{}{}
					<-releaseFirst
					return connWithUsers([]string{"New winner"}, map[string][]string{"alice": {"New winner"}}), nil
				}
			}
			type result struct {
				entry cache.UserEntry
				err   error
			}
			results := []chan result{make(chan result, 1), make(chan result, 1)}
			for i, d := range []*UserDirectory{first, second} {
				go func() { e, err := resolveOrRefresh(d, "alice", refresh); results[i] <- result{e, err} }()
			}
			for i := 0; i < 2; i++ {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("replicas did not both start lookup")
				}
			}
			close(releaseFirst)
			winner := receive(t, results[0])
			if winner.err != nil {
				t.Fatal(winner.err)
			}
			close(releaseSecond)
			loser := receive(t, results[1])
			if loser.err != nil {
				t.Fatal(loser.err)
			}
			if !slices.Equal(winner.entry.Record.Groups, loser.entry.Record.Groups) {
				t.Fatalf("stale result served: winner=%v loser=%v", winner.entry.Record.Groups, loser.entry.Record.Groups)
			}
			stored, err := first.store.Get(context.Background(), "alice")
			if err != nil || !slices.Equal(stored.Record.Groups, winner.entry.Record.Groups) {
				t.Fatalf("stale result persisted: %+v %v", stored, err)
			}
		})
	}
}

type interruptedStore struct {
	cache.UserStore
	first watch.Interface
	mu    sync.Mutex
	calls int
}

func (s *interruptedStore) Watch(ctx context.Context, version string) (watch.Interface, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls == 1 {
		return s.first, nil
	}
	return s.UserStore.Watch(ctx, version)
}
func TestInterruptedWatchRelistsAndRemovesDeletedUser(t *testing.T) {
	d, client := userTestDirectory(t)
	serveUsers(d, nil)
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	stream := watch.NewRaceFreeFake()
	store := &interruptedStore{UserStore: d.store, first: stream}
	d.store = store
	stop := make(chan struct{})
	defer close(stop)
	if err := d.Run(stop); err != nil {
		t.Fatal(err)
	}
	e, _ := d.cached("alice")
	// Bypass watch delivery to model a disconnected replica.
	if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("configmaps"), "proxy", e.Name); err != nil {
		t.Fatal(err)
	}
	stream.Stop()
	waitFor(t, "relist to remove deleted record", 3*time.Second, func() bool {
		_, ok := d.cached("alice")
		return !ok
	})
}

func TestLeadershipHandoverDiscardsOldLookup(t *testing.T) {
	old, _ := userTestDirectory(t)
	next := newTestReplica(t, old)
	serveUsers(old, map[string][]string{"alice": {"Original"}})
	if _, err := old.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	old.resolver.backends[0].dial = func(string) (conn, error) {
		close(entered)
		<-release
		return connWithUsers([]string{"Stale"}, map[string][]string{"alice": {"Stale"}}), nil
	}
	cycle, cancel := context.WithCancel(old.ctx)
	done := make(chan error, 1)
	go func() { done <- old.RefreshCached(cycle) }()
	receive(t, entered)
	cancel()
	serveUsers(next, map[string][]string{"alice": {"Current"}})
	if _, err := refreshOne(context.Background(), next, "alice"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := receive(t, done); err == nil {
		t.Fatal("old leadership cycle did not cancel")
	}
	waitFor(t, "old lookup to finish", time.Second, func() bool {
		old.callsMu.Lock()
		defer old.callsMu.Unlock()
		return len(old.calls) == 0
	})
	saved, err := old.store.Get(context.Background(), "alice")
	if err != nil || saved.Record.Groups[0] != "Current" {
		t.Fatalf("handover regressed record: %+v %v", saved, err)
	}
}
