// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type fakeConn struct {
	// entries maps a search base to the entries returned for it.
	entries map[string][]*goldap.Entry

	// searchFn, when set, answers the base scoped searches used to collect a
	// truncated attribute a window at a time.
	searchFn func(req *goldap.SearchRequest) (*goldap.SearchResult, error)

	// searches counts the base scoped searches answered by searchFn.
	searches int

	searchErr      error
	bindErr        error
	startTLSErr    error
	startTLSConfig *tls.Config

	bound bool
}

func (f *fakeConn) StartTLS(config *tls.Config) error {
	f.startTLSConfig = config.Clone()
	return f.startTLSErr
}

func (f *fakeConn) Bind(username, password string) error {
	if f.bindErr != nil {
		return f.bindErr
	}
	f.bound = true
	return nil
}

func (f *fakeConn) Search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}

	f.searches++

	if f.searchFn != nil {
		return f.searchFn(req)
	}

	return &goldap.SearchResult{Entries: f.entries[req.BaseDN]}, nil
}

func (f *fakeConn) Close() error {
	return nil
}

func entry(dn string, attrs map[string][]string) *goldap.Entry {
	e := &goldap.Entry{DN: dn}
	for name, values := range attrs {
		e.Attributes = append(e.Attributes, &goldap.EntryAttribute{Name: name, Values: values})
	}
	return e
}

const (
	// usersBase and groupsBase are the search bases of testBackend.
	usersBase  = "OU=Users,DC=example,DC=net"
	groupsBase = "OU=Groups,DC=example,DC=net"
)

func userDN(name string) string  { return "CN=" + name + "," + usersBase }
func groupDN(name string) string { return "CN=" + name + "," + groupsBase }

func testBackend(name string) *BackendConfig {
	return &BackendConfig{
		Name:               name,
		URLs:               []string{"ldaps://" + name + ".example.net:636"},
		BindDN:             "CN=svc,DC=example,DC=net",
		BindPassword:       "password",
		UserSearchBases:    []string{usersBase},
		UserFilter:         DefaultUserFilter,
		UsernameAttribute:  DefaultUsernameAttribute,
		GroupSearchBases:   []string{groupsBase},
		GroupFilter:        DefaultGroupFilter,
		GroupNameAttribute: DefaultGroupNameAttribute,
	}
}

func testConfig(backends ...*BackendConfig) *Config {
	if len(backends) == 0 {
		backends = []*BackendConfig{testBackend("ldap")}
	}

	return &Config{Cache: &CacheConfig{},
		Backends:        backends,
		RefreshInterval: NewDuration(time.Minute * 10),
	}
}

// newTestResolver returns a resolver whose backends search the given fake
// connections, in order, rather than a real server.

func newTestResolver(t *testing.T, config *Config, conns ...conn) *resolver {
	t.Helper()

	d, err := newResolver(config)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}

	if len(conns) != len(d.backends) {
		t.Fatalf("test gave %d connections for %d backends", len(conns), len(d.backends))
	}

	for i, c := range conns {
		d.backends[i].dial = func(string) (conn, error) { return c, nil }
	}

	return d
}

// connWithUsers returns a fake connection holding one group per name in groups
// and one user per key in users, membered into the named groups.

func connWithUsers(groups []string, users map[string][]string) *fakeConn {
	c := &fakeConn{entries: map[string][]*goldap.Entry{}}

	for _, group := range groups {
		// Separate entries, so that a test can change the group as read by
		// its DN without changing it as found under the base.
		dn, attrs := groupDN(group), map[string][]string{"cn": {group}}
		c.entries[dn] = []*goldap.Entry{entry(dn, attrs)}
		c.entries[groupsBase] = append(c.entries[groupsBase], entry(dn, attrs))
	}

	for username, memberOf := range users {
		dns := make([]string, 0, len(memberOf))
		for _, group := range memberOf {
			dns = append(dns, groupDN(group))
		}

		c.entries[usersBase] = append(c.entries[usersBase],
			entry(userDN(username), map[string][]string{
				"userPrincipalName": {username},
				"memberOf":          dns,
			}))
	}

	return c
}

// serveUsers makes every connection d opens a fresh directory holding users,
// each a member of the groups named for them, and returns the number of
// connections opened.
func serveUsers(d *UserDirectory, users map[string][]string) *atomic.Int64 {
	var groups []string
	for _, memberOf := range users {
		groups = append(groups, memberOf...)
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)

	var dials atomic.Int64
	d.resolver.backends[0].dial = func(string) (conn, error) {
		dials.Add(1)
		return connWithUsers(groups, users), nil
	}
	return &dials
}

func connWithRangedUser(username string, groups []string, window int) *fakeConn {
	c := &fakeConn{entries: map[string][]*goldap.Entry{}}

	dns := make([]string, len(groups))
	for i, group := range groups {
		dns[i] = groupDN(group)

		c.entries[groupsBase] = append(c.entries[groupsBase],
			entry(dns[i], map[string][]string{"cn": {group}}))
	}

	dn := userDN(username)

	// chunk is the entry the directory answers with for the values from first
	// onwards, naming the attribute the way it reports the window.
	chunk := func(first int) *goldap.Entry {
		last, name := first+window, fmt.Sprintf("memberOf;range=%d-%d", first, first+window-1)
		if last >= len(dns) {
			last, name = len(dns), fmt.Sprintf("memberOf;range=%d-*", first)
		}

		return &goldap.Entry{DN: dn, Attributes: []*goldap.EntryAttribute{
			{Name: "userPrincipalName", Values: []string{username}},
			{Name: name, Values: dns[first:last]},
		}}
	}

	c.entries[usersBase] = []*goldap.Entry{chunk(0)}

	c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
		var first int
		if _, err := fmt.Sscanf(req.Attributes[0], "memberOf;range=%d-*", &first); err != nil {
			return nil, fmt.Errorf("unexpected attribute %q", req.Attributes[0])
		}

		return &goldap.SearchResult{Entries: []*goldap.Entry{chunk(first)}}, nil
	}

	return c
}

// A truncated memberOf comes back under a description that is not the one that
// was asked for, so ignoring the range leaves the users in the most groups -
// who tend to be the ones with the most access - holding no groups at all.

func userTestDirectory(t *testing.T) (*UserDirectory, *fake.Clientset) {
	t.Helper()
	config := testConfig()
	config.Cache = &CacheConfig{Namespace: "proxy"}
	client := fake.NewClientset()
	var revision atomic.Int64
	revision.Store(100)
	client.PrependReactor("create", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		action.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap).ResourceVersion = fmt.Sprint(revision.Add(1))
		return false, nil, nil
	})
	client.PrependReactor("update", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		incoming := action.(ktesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		obj, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("configmaps"), "proxy", incoming.Name)
		if err != nil {
			return true, nil, err
		}
		if incoming.ResourceVersion != obj.(*corev1.ConfigMap).ResourceVersion {
			return true, nil, apierrors.NewConflict(corev1.Resource("configmaps"), incoming.Name, fmt.Errorf("resource version changed"))
		}
		incoming.ResourceVersion = fmt.Sprint(revision.Add(1))
		return false, nil, nil
	})
	client.PrependReactor("list", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		obj, err := client.Tracker().List(corev1.SchemeGroupVersion.WithResource("configmaps"), corev1.SchemeGroupVersion.WithKind("ConfigMap"), "proxy")
		if err != nil {
			return true, nil, err
		}
		obj.(*corev1.ConfigMapList).ResourceVersion = fmt.Sprint(revision.Load())
		return true, obj, nil
	})
	store, err := cache.NewConfigMaps(client, "proxy", config.UserRecordFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewUserDirectory(config, store, func() context.Context { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.cancel)
	return d, client
}

func userTestEntry(t *testing.T, d *UserDirectory, version string, groups ...string) cache.UserEntry {
	t.Helper()
	record, err := cache.NewUserRecord("alice", groups, d.resolver.fingerprint, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	name, _ := cache.UserConfigMapName("alice")
	return cache.UserEntry{Name: name, ResourceVersion: version, Record: record}
}

// refreshOne refreshes key as a batch of one, as the refresh cycle would.
func refreshOne(ctx context.Context, d *UserDirectory, key string) (cache.UserEntry, error) {
	result := d.refreshBatch(ctx, []string{key}, nil)[0]
	return result.entry, result.err
}

// resolveOrRefresh looks key up as a request would, or refreshes it.
func resolveOrRefresh(d *UserDirectory, key string, refresh bool) (cache.UserEntry, error) {
	if refresh {
		return refreshOne(context.Background(), d, key)
	}
	return d.resolve(context.Background(), key)
}

func newTestReplica(t *testing.T, source *UserDirectory) *UserDirectory {
	t.Helper()
	replica, err := NewUserDirectory(source.resolver.config, source.store, source.leadership)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replica.cancel)
	return replica
}

func waitFor(t *testing.T, description string, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if ready() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for test result")
	}
	var zero T
	return zero
}
