// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
)

// persistingConfig is a standalone proxy that writes what it builds, which is
// what a single user refresh has to update as well as the mapping in memory.
func persistingConfig(backends ...*BackendConfig) *Config {
	config := testConfig(backends...)
	config.Cache = &CacheConfig{
		Type:             CacheTypeKubernetesSecret,
		KubernetesSecret: &SecretCacheConfig{Name: "mapping"},
	}

	return config
}

// addUser puts a user into a fake connection after it has been built from, as
// a directory gaining one between rebuilds does.
func addUser(c *fakeConn, username string, groups ...string) {
	dns := make([]string, 0, len(groups))
	for _, group := range groups {
		dns = append(dns, "CN="+group+",OU=Groups,DC=example,DC=net")
	}

	c.entries["OU=Users,DC=example,DC=net"] = append(c.entries["OU=Users,DC=example,DC=net"],
		entry("CN="+username+",OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {username},
			"memberOf":          dns,
		}))
}

// addGroup puts a group into a fake connection after it has been built from,
// as a directory gaining one between rebuilds does. It is resolvable both by a
// sweep of the search base and by a base scoped search for its own DN, which is
// how a real directory answers for it.
func addGroup(c *fakeConn, name string) {
	dn := "CN=" + name + ",OU=Groups,DC=example,DC=net"
	group := entry(dn, map[string][]string{"cn": {name}})

	c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"], group)
	c.entries[dn] = []*goldap.Entry{group}
}

func TestRefreshUserFindsAUserTheMappingDoesNotHold(t *testing.T) {
	c := connWithUsers([]string{"admins", "devs"}, map[string][]string{
		"alice@example.net": {"admins"},
	})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if _, ok := d.Groups("bob@example.net"); ok {
		t.Fatal("expected the rebuild not to have found a user the directory did not hold yet")
	}

	// The directory gains the user after the rebuild that would have found
	// them, which is the whole situation this exists for.
	addUser(c, "bob@example.net", "devs")

	stats, err := d.RefreshUser(context.Background(), "bob@example.net")
	if err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	if !stats.Found || !stats.Changed || stats.Groups != 1 {
		t.Errorf("unexpected stats: %+v", stats)
	}

	if groups, ok := d.Groups("bob@example.net"); !ok || !reflect.DeepEqual(groups, []string{"devs"}) {
		t.Errorf("expected the refreshed user to be served, got %v, %t", groups, ok)
	}

	// Everybody else is left exactly as the rebuild left them.
	if groups, _ := d.Groups("alice@example.net"); !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the rest of the mapping to be untouched, got %v", groups)
	}
}

func TestRefreshUserMergesEveryBackend(t *testing.T) {
	first := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	second := connWithUsers([]string{"devs"}, map[string][]string{"alice@example.net": {"devs"}})

	d := newTestDirectory(t, testConfig(testBackend("first"), testBackend("second")), first, second)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	addUser(first, "bob@example.net", "admins")
	addUser(second, "bob@example.net", "devs")

	if _, err := d.RefreshUser(context.Background(), "bob@example.net"); err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	// The union of what each directory holds, exactly as a rebuild merges them.
	groups, ok := d.Groups("bob@example.net")
	if !ok {
		t.Fatal("expected the user to have been found")
	}

	if exp := []string{"admins", "devs"}; !reflect.DeepEqual(groups, exp) {
		t.Errorf("unexpected groups, exp=%v got=%v", exp, groups)
	}
}

// A backend that cannot be searched fails the refresh rather than being left
// out of it, as it fails a rebuild: the user would otherwise be given an
// identity missing whatever the unreachable directory holds for them.
func TestRefreshUserFailsWhenABackendCannotBeSearched(t *testing.T) {
	first := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	second := connWithUsers([]string{"devs"}, map[string][]string{"alice@example.net": {"devs"}})

	d := newTestDirectory(t, testConfig(testBackend("first"), testBackend("second")), first, second)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	addUser(first, "bob@example.net", "admins")
	second.searchErr = errors.New("connection reset")

	_, err := d.RefreshUser(context.Background(), "bob@example.net")
	if err == nil {
		t.Fatal("expected an error when a backend could not be searched, got none")
	}

	if exp := "second"; !strings.Contains(err.Error(), exp) {
		t.Errorf("expected the failing backend %q to be named, got %q", exp, err)
	}

	if _, ok := d.Groups("bob@example.net"); ok {
		t.Error("expected a failed refresh to leave the mapping alone")
	}
}

func TestRefreshUserRefusesAnAmbiguousUser(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// Two entries claiming one username: which of them a request should run as
	// is no clearer for having been asked about one user.
	c.entries["OU=Users,DC=example,DC=net"] = append(c.entries["OU=Users,DC=example,DC=net"],
		entry("CN=bob,OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"bob@example.net"},
		}),
		entry("CN=bob2,OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"bob@example.net"},
		}))

	_, err := d.RefreshUser(context.Background(), "bob@example.net")
	if err == nil {
		t.Fatal("expected an error refreshing a user held twice, got none")
	}

	if exp := "so the groups to give them are ambiguous"; !strings.Contains(err.Error(), exp) {
		t.Errorf("expected an error containing %q, got %q", exp, err)
	}

	if _, ok := d.Groups("bob@example.net"); ok {
		t.Error("expected an ambiguous user not to be served")
	}
}

// Adding a user to a group that was created since the last rebuild is the
// change somebody is most likely to be asking to have picked up, so resolving
// their membership only against what that rebuild found would leave the refresh
// doing nothing in the case it exists for.
func TestRefreshUserFindsAGroupCreatedSinceTheLastRebuild(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	addGroup(c, "new")
	addUser(c, "bob@example.net", "admins", "new")

	if _, err := d.RefreshUser(context.Background(), "bob@example.net"); err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	groups, _ := d.Groups("bob@example.net")
	if exp := []string{"admins", "new"}; !reflect.DeepEqual(groups, exp) {
		t.Errorf("unexpected groups, exp=%v got=%v", exp, groups)
	}
}

// A group outside the configured search bases is not mapped onto a user by a
// rebuild, and is not mapped onto them by a refresh either - and answering that
// from the DN means no search is made for it at all.
func TestRefreshUserIgnoresGroupsOutsideTheSearchBases(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// Held in an OU the configuration does not name, and resolvable if anybody
	// were to go looking for it.
	outside := "CN=everyone,OU=Other,DC=example,DC=net"
	c.entries[outside] = []*goldap.Entry{
		entry(outside, map[string][]string{"cn": {"everyone"}}),
	}

	c.entries["OU=Users,DC=example,DC=net"] = append(c.entries["OU=Users,DC=example,DC=net"],
		entry("CN=bob@example.net,OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"bob@example.net"},
			"memberOf":          {"CN=admins,OU=Groups,DC=example,DC=net", outside},
		}))

	var searched []string
	c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
		searched = append(searched, req.BaseDN)
		return &goldap.SearchResult{Entries: c.entries[req.BaseDN]}, nil
	}

	if _, err := d.RefreshUser(context.Background(), "bob@example.net"); err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	groups, _ := d.Groups("bob@example.net")
	if exp := []string{"admins"}; !reflect.DeepEqual(groups, exp) {
		t.Errorf("unexpected groups, exp=%v got=%v", exp, groups)
	}

	for _, base := range searched {
		if base == outside {
			t.Error("expected a group outside the search bases to be answered without a search")
		}
	}
}

// A DN under a group search base that the group filter does not select is not a
// group as this backend defines one, and a rebuild would not have mapped it.
func TestRefreshUserIgnoresANonGroupUnderTheSearchBase(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// Under the base, but the base scoped search for it comes back empty, as
	// it does for an entry the filter does not match.
	addUser(c, "bob@example.net", "admins", "notagroup")

	if _, err := d.RefreshUser(context.Background(), "bob@example.net"); err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	groups, _ := d.Groups("bob@example.net")
	if exp := []string{"admins"}; !reflect.DeepEqual(groups, exp) {
		t.Errorf("unexpected groups, exp=%v got=%v", exp, groups)
	}
}

// A memberOf naming a group that has since been deleted is an ordinary state,
// not a directory that cannot be searched.
func TestRefreshUserIgnoresADeletedGroup(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	addUser(c, "bob@example.net", "admins", "gone")

	c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
		if req.BaseDN == "CN=gone,OU=Groups,DC=example,DC=net" {
			return nil, goldap.NewError(goldap.LDAPResultNoSuchObject, errors.New("no such object"))
		}

		return &goldap.SearchResult{Entries: c.entries[req.BaseDN]}, nil
	}

	if _, err := d.RefreshUser(context.Background(), "bob@example.net"); err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	groups, _ := d.Groups("bob@example.net")
	if exp := []string{"admins"}; !reflect.DeepEqual(groups, exp) {
		t.Errorf("unexpected groups, exp=%v got=%v", exp, groups)
	}
}

// Once the DN is discarded there is no way for RBAC to tell two directory
// groups of one name apart, so a new group taking the name of one already in
// the mapping is the ambiguity a rebuild refuses.
func TestRefreshUserRefusesANewGroupOfAnExistingName(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// A second entry, elsewhere under the search base, emitting "admins" too.
	clash := "CN=admins,OU=Nested,OU=Groups,DC=example,DC=net"
	c.entries[clash] = []*goldap.Entry{entry(clash, map[string][]string{"cn": {"admins"}})}

	c.entries["OU=Users,DC=example,DC=net"] = append(c.entries["OU=Users,DC=example,DC=net"],
		entry("CN=bob@example.net,OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"bob@example.net"},
			"memberOf":          {clash},
		}))

	_, err := d.RefreshUser(context.Background(), "bob@example.net")
	if err == nil {
		t.Fatal("expected an error for two groups of one name, got none")
	}

	if exp := "the authorization identity is ambiguous"; !strings.Contains(err.Error(), exp) {
		t.Errorf("expected an error containing %q, got %q", exp, err)
	}
}

// A refresh that has to discover this many groups is looking at a mapping too
// far out of date for one user to be the right unit of work.
func TestRefreshUserRefusesTooManyMissingGroups(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups := make([]string, 0, maxGroupDiscoveries+1)
	for i := 0; i <= maxGroupDiscoveries; i++ {
		name := fmt.Sprintf("new-%d", i)
		addGroup(c, name)
		groups = append(groups, name)
	}

	addUser(c, "bob@example.net", groups...)

	_, err := d.RefreshUser(context.Background(), "bob@example.net")
	if err == nil {
		t.Fatal("expected an error for a mapping this far out of date, got none")
	}

	if exp := "refresh the whole mapping rather than one user"; !strings.Contains(err.Error(), exp) {
		t.Errorf("expected an error containing %q, got %q", exp, err)
	}
}

func TestRefreshUserEscapesTheUsername(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	var filters []string
	c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
		filters = append(filters, req.Filter)
		return &goldap.SearchResult{}, nil
	}

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if _, err := d.RefreshUser(context.Background(), "bob*)(objectClass=*"); err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	if len(filters) != 1 {
		t.Fatalf("expected one search, got %d", len(filters))
	}

	// The name comes from a request, so it reaches the filter escaped: one
	// carrying an asterisk or a parenthesis must not be able to widen the
	// search it appears in.
	if strings.Contains(filters[0], "bob*)") {
		t.Errorf("expected the username to have been escaped, got filter %q", filters[0])
	}

	if exp := `\2a`; !strings.Contains(filters[0], exp) {
		t.Errorf("expected the filter to contain %q, got %q", exp, filters[0])
	}
}

func TestRefreshUserPersistsTheChange(t *testing.T) {
	c := connWithUsers([]string{"admins", "devs"}, map[string][]string{
		"alice@example.net": {"admins"},
	})

	store := &memoryStore{}
	config := persistingConfig()

	d, err := New(config, store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if store.saves != 1 {
		t.Fatalf("expected the rebuild to have been persisted, got %d saves", store.saves)
	}

	addUser(c, "bob@example.net", "devs")

	if _, err := d.RefreshUser(context.Background(), "bob@example.net"); err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	// The mapping is written out, so the user survives a restart and reaches
	// the readers of a builder rather than living in this proxy alone.
	if store.saves != 2 {
		t.Errorf("expected the refreshed user to have been persisted, got %d saves", store.saves)
	}

	restored, err := New(config, store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}

	if !restored.restore() {
		t.Fatal("expected the persisted mapping to be restored")
	}

	if groups, ok := restored.Groups("bob@example.net"); !ok || !reflect.DeepEqual(groups, []string{"devs"}) {
		t.Errorf("expected the persisted mapping to hold the refreshed user, got %v, %t", groups, ok)
	}
}

// The store is written before the mapping is swapped in, so a store that
// cannot be written leaves the refresh failed rather than leaving this proxy
// serving something nothing else will ever see.
func TestRefreshUserFailsWhenTheStoreCannotBeWritten(t *testing.T) {
	c := connWithUsers([]string{"admins", "devs"}, map[string][]string{
		"alice@example.net": {"admins"},
	})

	store := &memoryStore{}

	d, err := New(persistingConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	addUser(c, "bob@example.net", "devs")
	store.saveErr = errors.New("secrets \"mapping\" is forbidden")

	if _, err := d.RefreshUser(context.Background(), "bob@example.net"); err == nil {
		t.Fatal("expected an error when the mapping could not be persisted, got none")
	}

	if _, ok := d.Groups("bob@example.net"); ok {
		t.Error("expected the mapping not to have been swapped in when the store refused it")
	}
}

func TestRefreshUserLeavesTheStoreAloneWhenNothingChanged(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := &memoryStore{}

	d, err := New(persistingConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	saves := store.saves

	stats, err := d.RefreshUser(context.Background(), "alice@example.net")
	if err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	if stats.Changed {
		t.Error("expected a user whose groups have not moved to report no change")
	}

	// There is no partial write, so a refresh that found what was already
	// being served would rewrite the whole mapping for nothing.
	if store.saves != saves {
		t.Errorf("expected no write when nothing changed, got %d saves", store.saves-saves)
	}
}

func TestRefreshUserDropsAUserTheDirectoryNoLongerHolds(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{
		"alice@example.net": {"admins"},
		"bob@example.net":   {"admins"},
	})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// Bob leaves the directory.
	remaining := make([]*goldap.Entry, 0)
	for _, e := range c.entries["OU=Users,DC=example,DC=net"] {
		if !strings.HasPrefix(e.DN, "CN=bob@example.net,") {
			remaining = append(remaining, e)
		}
	}
	c.entries["OU=Users,DC=example,DC=net"] = remaining

	stats, err := d.RefreshUser(context.Background(), "bob@example.net")
	if err != nil {
		t.Fatalf("unexpected error refreshing the user: %s", err)
	}

	if stats.Found || !stats.Changed {
		t.Errorf("unexpected stats: %+v", stats)
	}

	// Serving their old groups would be serving an entry the next rebuild
	// would drop anyway.
	if groups, ok := d.Groups("bob@example.net"); ok {
		t.Errorf("expected the user to have been dropped, got %v", groups)
	}

	if _, ok := d.Groups("alice@example.net"); !ok {
		t.Error("expected everybody else to be left alone")
	}
}

func TestRefreshUserNeedsAMapping(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if _, err := d.RefreshUser(context.Background(), "alice@example.net"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("expected %q, got %v", ErrNoMapping, err)
	}
}

// A reader holds no credentials and no description of the directory layout, so
// there is nothing for it to search. Its refresh endpoint is not served at all,
// which makes this a guard rather than a path anybody reaches.
func TestRefreshUserRefusesAReader(t *testing.T) {
	store := &memoryStore{}

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}

	_, err = reader.RefreshUser(context.Background(), "alice@example.net")
	if err == nil {
		t.Fatal("expected a reader to refuse to refresh a user, got no error")
	}

	if exp := "never reaches a directory"; !strings.Contains(err.Error(), exp) {
		t.Errorf("expected an error containing %q, got %q", exp, err)
	}
}

// A rebuild landing while one user is being refreshed must not lose either of
// them: whichever finishes second writes a mapping that accounts for the first.
func TestRefreshUserAndRebuildDoNotOverwriteEachOther(t *testing.T) {
	c := connWithUsers([]string{"admins", "devs"}, map[string][]string{
		"alice@example.net": {"admins"},
	})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	addUser(c, "bob@example.net", "devs")

	// A rebuild and a single user refresh dial separately, so give each its
	// own connection over the same entries rather than having them share the
	// bookkeeping of one fake.
	d.backends[0].dial = func(string) (conn, error) {
		return &fakeConn{entries: c.entries}, nil
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		if _, err := d.RefreshUser(context.Background(), "bob@example.net"); err != nil {
			t.Errorf("unexpected error refreshing the user: %s", err)
		}
	}()

	go func() {
		defer wg.Done()

		if err := d.Refresh(); err != nil {
			t.Errorf("unexpected error refreshing: %s", err)
		}
	}()

	wg.Wait()

	// Both were looking at a directory holding both users, so whichever order
	// they landed in, that is what is being served.
	for _, username := range []string{"alice@example.net", "bob@example.net"} {
		if _, ok := d.Groups(username); !ok {
			t.Errorf("expected %q to be served", username)
		}
	}
}

// By default any authenticated user may ask for a refresh, so a burst of
// requests for one user must not become a burst of writes of the whole
// mapping. Whichever gets there first writes it; the rest find nothing left to
// change.
func TestRefreshUserWritesOnceForConcurrentCallers(t *testing.T) {
	c := connWithUsers([]string{"admins", "devs"}, map[string][]string{
		"alice@example.net": {"admins"},
	})

	store := &memoryStore{}

	d, err := New(persistingConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) {
		return &fakeConn{entries: c.entries}, nil
	}

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	addUser(c, "bob@example.net", "devs")
	saves := store.saves

	var wg sync.WaitGroup
	changes := make([]bool, 10)
	for i := range changes {
		wg.Add(1)
		go func() {
			defer wg.Done()

			stats, err := d.RefreshUser(context.Background(), "bob@example.net")
			if err != nil {
				t.Errorf("unexpected error refreshing the user: %s", err)
				return
			}

			changes[i] = stats.Changed
		}()
	}
	wg.Wait()

	var changed int
	for _, c := range changes {
		if c {
			changed++
		}
	}

	if changed != 1 {
		t.Errorf("expected exactly one caller to report a change, got %d", changed)
	}

	if got := store.saves - saves; got != 1 {
		t.Errorf("expected exactly one write of the mapping, got %d", got)
	}
}

// A caller that has gone away before the directories are searched is not made
// to wait on them: nothing is left to hand the result to.
func TestRefreshUserStopsForACancelledCaller(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	searched := c.searches
	if _, err := d.RefreshUser(ctx, "alice@example.net"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected the refresh to report the cancellation, got %v", err)
	}

	if c.searches != searched {
		t.Errorf("expected no search to have been made, got %d", c.searches-searched)
	}
}
