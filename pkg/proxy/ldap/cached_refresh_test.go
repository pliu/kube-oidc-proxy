// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestRefreshOnlyCachedUsersIncludingAbsent(t *testing.T) {
	d, _ := userTestDirectory(t)
	calls := serveUsers(d, map[string][]string{"alice": {"Old"}, "uncached": {"Old"}})
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if groups, err := d.Resolve(context.Background(), "absent"); err != nil || len(groups) != 0 {
		t.Fatalf("%v %v", groups, err)
	}
	before := calls.Load()
	if groups, err := d.Resolve(context.Background(), "absent"); err != nil || len(groups) != 0 {
		t.Fatalf("cached absent user: %v %v", groups, err)
	}
	if calls.Load() != before {
		t.Fatal("absent user cache hit queried LDAP")
	}
	calls = serveUsers(d, map[string][]string{"absent": {"New"}, "uncached": {"New"}})
	if err := d.RefreshCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("refresh did not search the two cached users as one batch")
	}
	alice, ok := d.cached("alice")
	if !ok || len(alice.Record.Groups) != 0 {
		t.Fatal("absent user retained old grants")
	}
	absent, ok := d.cached("absent")
	if !ok || len(absent.Record.Groups) != 1 || absent.Record.Groups[0] != "New" {
		t.Fatal("newly provisioned user was not refreshed")
	}
	if _, ok := d.cached("uncached"); ok {
		t.Fatal("refresh enumerated uncached user")
	}
}

func TestPeriodicRefreshRequiresLeadership(t *testing.T) {
	d, _ := userTestDirectory(t)
	d.resolver.config.RefreshInterval = NewDuration(10 * time.Millisecond)
	calls := serveUsers(d, nil)
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
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

	groups, err := d.Resolve(context.Background(), "alice")
	if err != nil || len(groups) != 1 || groups[0] != "New" {
		t.Fatalf("shared result lost: %v %v", groups, err)
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

// cacheUsers stores a record with the given groups for each username.
func cacheUsers(t *testing.T, d *UserDirectory, groups []string, usernames ...string) {
	t.Helper()
	users := make(map[string][]string, len(usernames))
	for _, username := range usernames {
		users[username] = groups
	}
	serveUsers(d, users)
	for _, username := range usernames {
		if _, err := d.Resolve(context.Background(), username); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRefreshBatchesLDAPAndKubernetesIO(t *testing.T) {
	d, client := userTestDirectory(t)
	usernames := []string{"alice", "bob", "carol"}
	cacheUsers(t, d, []string{"Old"}, usernames...)

	c := connWithUsers([]string{"Dev", "Ops"}, map[string][]string{
		"alice": {"Dev", "Ops"}, "bob": {"Dev", "Ops"}, "carol": {"Dev"}, "uncached": {"Ops"},
	})
	var userSearches, groupReads, identityChecks int
	var filter string
	c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
		switch {
		case req.BaseDN == usersBase:
			userSearches++
			filter = req.Filter
		case req.Scope == goldap.ScopeBaseObject:
			groupReads++
		default:
			identityChecks++
		}
		return &goldap.SearchResult{Entries: c.entries[req.BaseDN]}, nil
	}
	var dials atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) { dials.Add(1); return c, nil }

	client.ClearActions()
	if err := d.RefreshCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	verbs := map[string]int{}
	for _, action := range client.Actions() {
		verbs[action.GetVerb()]++
	}
	if verbs["list"] != 1 || verbs["get"] != 0 || verbs["update"] != len(usernames) {
		t.Fatalf("expected one list, no gets and an update per user, got %v", verbs)
	}
	if dials.Load() != 1 || userSearches != 1 {
		t.Fatalf("expected one connection and one user search, got %d and %d", dials.Load(), userSearches)
	}
	for _, username := range usernames {
		if !strings.Contains(filter, "(userPrincipalName="+username+")") {
			t.Errorf("batch filter %s does not name %s", filter, username)
		}
	}
	if groupReads != 2 || identityChecks != 2 {
		t.Fatalf("expected each group read and checked once, got %d reads and %d checks", groupReads, identityChecks)
	}
	for username, exp := range map[string]string{"alice": "Dev,Ops", "bob": "Dev,Ops", "carol": "Dev"} {
		entry, ok := d.cached(username)
		if !ok || strings.Join(entry.Record.Groups, ",") != exp {
			t.Errorf("%s: expected groups %s, got %+v", username, exp, entry.Record)
		}
	}
	if _, ok := d.cached("uncached"); ok {
		t.Fatal("refresh enumerated uncached user")
	}
}

func TestRefreshSplitsUsersIntoBatches(t *testing.T) {
	d, _ := userTestDirectory(t)
	d.resolver.config.RefreshBatchSize = 2
	usernames := []string{"u1", "u2", "u3", "u4", "u5"}
	cacheUsers(t, d, nil, usernames...)

	var mu sync.Mutex
	var batches []int
	users := make(map[string][]string, len(usernames))
	for _, username := range usernames {
		users[username] = nil
	}
	d.resolver.backends[0].dial = func(string) (conn, error) {
		c := connWithUsers(nil, users)
		c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
			mu.Lock()
			batches = append(batches, strings.Count(req.Filter, "(userPrincipalName="))
			mu.Unlock()
			return &goldap.SearchResult{Entries: c.entries[req.BaseDN]}, nil
		}
		return c, nil
	}
	if err := d.RefreshCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(batches) != "[2 2 1]" {
		t.Fatalf("expected batches of 2, 2 and 1 users, got %v", batches)
	}
}

func TestRefreshBatchIsolatesRejectedUser(t *testing.T) {
	d, _ := userTestDirectory(t)
	cacheUsers(t, d, []string{"Old"}, "alice", "bob")

	c := connWithUsers([]string{"New"}, map[string][]string{"alice": {"New"}, "bob": {"New"}})
	// A second entry claiming bob makes his identity ambiguous.
	c.entries[usersBase] = append(c.entries[usersBase],
		entry(userDN("bob2"), map[string][]string{"userPrincipalName": {"bob"}}))
	d.resolver.backends[0].dial = func(string) (conn, error) { return c, nil }

	err := d.RefreshCached(context.Background())
	var duplicate *duplicateUserError
	if !errors.As(err, &duplicate) || duplicate.username != "bob" {
		t.Fatalf("expected bob to be rejected, got %v", err)
	}
	if alice, ok := d.cached("alice"); !ok || strings.Join(alice.Record.Groups, ",") != "New" {
		t.Fatal("a rejected user held back the rest of the batch")
	}
	if bob, ok := d.cached("bob"); !ok || strings.Join(bob.Record.Groups, ",") != "Old" {
		t.Fatal("rejected user lost their previous record")
	}
}

func TestRefreshBatchFailsWhenBackendCannotBeSearched(t *testing.T) {
	d, _ := userTestDirectory(t)
	cacheUsers(t, d, []string{"Old"}, "alice", "bob")
	d.resolver.backends[0].dial = func(string) (conn, error) {
		return &fakeConn{searchErr: goldap.NewError(goldap.LDAPResultBusy, errors.New("busy"))}, nil
	}
	err := d.RefreshCached(context.Background())
	if err == nil || strings.Count(err.Error(), "failed to search for 2 users") != 2 {
		t.Fatalf("expected both users to fail with the batch, got %v", err)
	}
	for _, username := range []string{"alice", "bob"} {
		if entry, ok := d.cached(username); !ok || strings.Join(entry.Record.Groups, ",") != "Old" {
			t.Fatalf("%s lost their previous record", username)
		}
	}
}

// afterListStore runs hook once a List has been answered.
type afterListStore struct {
	cache.UserStore
	hook func()
}

func (s *afterListStore) List(ctx context.Context) (cache.UserList, error) {
	list, err := s.UserStore.List(ctx)
	if err == nil && s.hook != nil {
		s.hook()
		s.hook = nil
	}
	return list, err
}

func TestRefreshKeepsRecordCommittedSinceTheList(t *testing.T) {
	d, _ := userTestDirectory(t)
	cacheUsers(t, d, []string{"Old"}, "alice")
	store := d.store
	d.store = &afterListStore{UserStore: store, hook: func() {
		// Another replica commits a record after the cycle listed alice's.
		current, err := store.Get(context.Background(), "alice")
		if err != nil {
			t.Fatal(err)
		}
		record, err := cache.NewUserRecord("alice", []string{"Other"}, d.resolver.fingerprint, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Upsert(context.Background(), record, current.ResourceVersion); err != nil {
			t.Fatal(err)
		}
	}}
	serveUsers(d, map[string][]string{"alice": {"New"}})
	if err := d.RefreshCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	if alice, ok := d.cached("alice"); !ok || strings.Join(alice.Record.Groups, ",") != "Other" {
		t.Fatal("a write against the listed version replaced the record committed since")
	}
}

func TestRefreshFailsWhenRecordsCannotBeListed(t *testing.T) {
	d, client := userTestDirectory(t)
	cacheUsers(t, d, []string{"Old"}, "alice", "bob")
	client.PrependReactor("list", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	dials := serveUsers(d, nil)
	if err := d.RefreshCached(context.Background()); err == nil || !strings.Contains(err.Error(), "apiserver unavailable") {
		t.Fatalf("expected the list failure, got %v", err)
	}
	if dials.Load() != 0 {
		t.Fatal("refresh searched LDAP without the records to compare against")
	}
	for _, username := range []string{"alice", "bob"} {
		if entry, ok := d.cached(username); !ok || strings.Join(entry.Record.Groups, ",") != "Old" {
			t.Fatalf("%s lost their previous record", username)
		}
	}
}
