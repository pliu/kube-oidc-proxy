// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

type gatedLookupStore struct {
	cache.UserStore
	gateGet bool
	entered chan string
	release <-chan struct{}
	gets    atomic.Int64
}

func (s *gatedLookupStore) wait(ctx context.Context, key string) error {
	select {
	case s.entered <- key:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *gatedLookupStore) Get(ctx context.Context, key string) (cache.UserEntry, error) {
	s.gets.Add(1)
	if s.gateGet {
		if err := s.wait(ctx, key); err != nil {
			return cache.UserEntry{}, err
		}
	}
	return s.UserStore.Get(ctx, key)
}
func (s *gatedLookupStore) Upsert(ctx context.Context, record *cache.UserRecord, version string) (cache.UserEntry, error) {
	if !s.gateGet {
		if err := s.wait(ctx, record.Username); err != nil {
			return cache.UserEntry{}, err
		}
	}
	return s.UserStore.Upsert(ctx, record, version)
}

func TestLookupAdmissionBoundsReadAndPersistence(t *testing.T) {
	for _, stage := range []string{"read", "persistence"} {
		t.Run(stage, func(t *testing.T) {
			d, _ := userTestDirectory(t)
			d.resolver.config.LookupConcurrency = 2
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			store := &gatedLookupStore{UserStore: d.store, gateGet: stage == "read", entered: make(chan string, 8), release: release}
			d.store = store
			d.resolver.backends[0].dial = func(string) (conn, error) { return connWithUsers(nil, nil), nil }
			d.apply(userTestEntry(t, d, "1000", "CachedGroup"), false)
			results := make(chan error, 2)
			for _, key := range []string{"bob", "carol"} {
				go func() { _, _, err := d.Resolve(context.Background(), key); results <- err }()
			}
			for i := 0; i < 2; i++ {
				select {
				case <-store.entered:
				case <-time.After(time.Second):
					t.Fatal("lookup did not reach blocked I/O")
				}
			}
			// Distinct identities must be rejected before they create more API work.
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _, err := d.Resolve(context.Background(), fmt.Sprintf("new-%d", i))
					if !errors.Is(err, ErrLookupCapacity) {
						t.Errorf("overload returned %v", err)
					}
				}()
			}
			wg.Wait()
			if store.gets.Load() != 2 {
				t.Fatalf("overload caused extra reads: %d", store.gets.Load())
			}
			groups, found, err := d.Resolve(context.Background(), "alice")
			if err != nil || !found || len(groups) != 1 || groups[0] != "CachedGroup" {
				t.Fatalf("saturation blocked memory hit: %v %t %v", groups, found, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if _, _, err := d.Resolve(ctx, "bob"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("same-user waiter could not join: %v", err)
			}
			if err := d.RefreshCached(context.Background()); !errors.Is(err, ErrLookupCapacity) {
				t.Fatalf("refresh bypassed admission: %v", err)
			}
			unblock()
			for i := 0; i < 2; i++ {
				select {
				case err := <-results:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("admitted lookup did not complete")
				}
			}
			if _, _, err := d.Resolve(context.Background(), "later"); err != nil {
				t.Fatalf("capacity was not released: %v", err)
			}
		})
	}
}
