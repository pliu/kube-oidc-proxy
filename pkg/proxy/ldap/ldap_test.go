// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

type fakeConn struct {
	// entries maps a search base to the entries returned for it.
	entries map[string][]*goldap.Entry

	// searchFn, when set, answers the base scoped searches used to collect a
	// truncated attribute a window at a time.
	searchFn func(req *goldap.SearchRequest) (*goldap.SearchResult, error)

	// searches counts the base scoped searches answered by searchFn.
	searches int

	searchErr error
	bindErr   error

	bound  bool
	closed bool
}

func (f *fakeConn) StartTLS(*tls.Config) error { return nil }

func (f *fakeConn) Bind(username, password string) error {
	if f.bindErr != nil {
		return f.bindErr
	}
	f.bound = true
	return nil
}

func (f *fakeConn) SearchWithPaging(req *goldap.SearchRequest, pagingSize uint32) (*goldap.SearchResult, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return &goldap.SearchResult{Entries: f.entries[req.BaseDN]}, nil
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
	f.closed = true
	return nil
}

func entry(dn string, attrs map[string][]string) *goldap.Entry {
	e := &goldap.Entry{DN: dn}
	for name, values := range attrs {
		e.Attributes = append(e.Attributes, &goldap.EntryAttribute{Name: name, Values: values})
	}
	return e
}

func testBackend(name string) *BackendConfig {
	return &BackendConfig{
		Name:               name,
		URLs:               []string{"ldaps://" + name + ".example.net:636"},
		BindDN:             "CN=svc,DC=example,DC=net",
		BindPassword:       "password",
		UserSearchBases:    []string{"OU=Users,DC=example,DC=net"},
		UserFilter:         DefaultUserFilter,
		UsernameAttribute:  DefaultUsernameAttribute,
		GroupSearchBases:   []string{"OU=Groups,DC=example,DC=net"},
		GroupFilter:        DefaultGroupFilter,
		GroupNameAttribute: DefaultGroupNameAttribute,
	}
}

func testConfig(backends ...*BackendConfig) *Config {
	if len(backends) == 0 {
		backends = []*BackendConfig{testBackend("ldap")}
	}

	return &Config{
		Backends:        backends,
		RefreshInterval: NewDuration(time.Minute * 10),
	}
}

// newTestDirectory returns a Directory whose backends search the given fake
// connections, in order, rather than a real server.
func newTestDirectory(t *testing.T, config *Config, conns ...conn) *Directory {
	t.Helper()

	d, err := New(config, nil)
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
		c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"],
			entry("CN="+group+",OU=Groups,DC=example,DC=net", map[string][]string{"cn": {group}}))
	}

	for username, memberOf := range users {
		dns := make([]string, 0, len(memberOf))
		for _, group := range memberOf {
			dns = append(dns, "CN="+group+",OU=Groups,DC=example,DC=net")
		}

		c.entries["OU=Users,DC=example,DC=net"] = append(c.entries["OU=Users,DC=example,DC=net"],
			entry("CN="+username+",OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {username},
				"memberOf":          dns,
			}))
	}

	return c
}

func TestNewValidatesConfig(t *testing.T) {
	tests := map[string]struct {
		mutate func(*Config)
		expErr string
	}{
		"no backends":             {func(c *Config) { c.Backends = nil }, "no LDAP backends configured"},
		"no name":                 {func(c *Config) { c.Backends[0].Name = "" }, "name must be set"},
		"no URL":                  {func(c *Config) { c.Backends[0].URLs = nil }, "at least one url must be set"},
		"no user search base":     {func(c *Config) { c.Backends[0].UserSearchBases = nil }, "at least one userSearchBase must be set"},
		"no group search base":    {func(c *Config) { c.Backends[0].GroupSearchBases = nil }, "at least one groupSearchBase must be set"},
		"a zero refresh interval": {func(c *Config) { c.RefreshInterval = NewDuration(0) }, "refreshInterval must be a positive duration"},
		"duplicate names": {
			func(c *Config) { c.Backends = append(c.Backends, testBackend("ldap")) },
			"duplicate backend name",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			test.mutate(config)

			_, err := New(config, nil)
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", test.expErr)
			}

			if !strings.Contains(err.Error(), test.expErr) {
				t.Errorf("expected an error containing %q, got %q", test.expErr, err)
			}
		})
	}
}

func TestRefreshBuildsMapping(t *testing.T) {
	c := &fakeConn{entries: map[string][]*goldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("CN=admins,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"admins"}}),
			entry("CN=devs,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"devs"}}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"alice@example.net"},
				"memberOf": {
					"CN=admins,OU=Groups,DC=example,DC=net",
					"CN=devs,OU=Groups,DC=example,DC=net",
					// Outside the configured group search base, so ignored.
					"CN=everyone,OU=Other,DC=example,DC=net",
				},
			}),
			entry("CN=bob,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"bob@example.net"},
			}),
		},
	}}

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if !c.bound {
		t.Error("expected the connection to have been bound")
	}
	if !c.closed {
		t.Error("expected the connection to have been closed")
	}

	tests := map[string]struct {
		username  string
		expGroups []string
		expFound  bool
	}{
		"user in groups":             {"alice@example.net", []string{"admins", "devs"}, true},
		"user in no groups":          {"bob@example.net", []string{}, true},
		"lookup is case insensitive": {"Alice@Example.net", []string{"admins", "devs"}, true},
		"unknown user":               {"eve@example.net", nil, false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			groups, ok := d.Groups(test.username)

			if ok != test.expFound {
				t.Errorf("expected found=%t, got %t", test.expFound, ok)
			}

			if !reflect.DeepEqual(groups, test.expGroups) {
				t.Errorf("expected groups %v, got %v", test.expGroups, groups)
			}
		})
	}

	stats := d.Stats()
	if stats.Users != 2 || stats.Groups != 2 {
		t.Errorf("expected stats of 2 users and 2 groups, got %d and %d", stats.Users, stats.Groups)
	}
	if stats.Source != SourceDirectory {
		t.Errorf("expected the mapping to be sourced from %q, got %q", SourceDirectory, stats.Source)
	}
	if len(stats.Backends) != 1 || stats.Backends[0].Name != "ldap" || stats.Backends[0].Users != 2 {
		t.Errorf("expected per backend stats for 2 users of backend \"ldap\", got %+v", stats.Backends)
	}
}

// A user held in more than one directory holds the union of their groups.
func TestRefreshMergesBackends(t *testing.T) {
	first := connWithUsers([]string{"admins", "shared"}, map[string][]string{
		"alice@example.net": {"admins", "shared"},
		"bob@example.net":   {"admins"},
	})

	second := connWithUsers([]string{"contractors", "shared"}, map[string][]string{
		"alice@example.net": {"contractors", "shared"},
		"carol@example.net": {"contractors"},
	})

	d := newTestDirectory(t, testConfig(testBackend("first"), testBackend("second")), first, second)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	tests := map[string]struct {
		username  string
		expGroups []string
	}{
		"a user in both backends holds the union of their groups": {
			"alice@example.net", []string{"admins", "contractors", "shared"},
		},
		"a user in only the first backend keeps their groups": {
			"bob@example.net", []string{"admins"},
		},
		"a user in only the second backend keeps their groups": {
			"carol@example.net", []string{"contractors"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			groups, ok := d.Groups(test.username)
			if !ok {
				t.Fatalf("expected %q to be found", test.username)
			}

			if !reflect.DeepEqual(groups, test.expGroups) {
				t.Errorf("expected groups %v, got %v", test.expGroups, groups)
			}
		})
	}

	if stats := d.Stats(); stats.Users != 3 || len(stats.Backends) != 2 {
		t.Errorf("expected 3 merged users across 2 backends, got %d users and %+v", stats.Users, stats.Backends)
	}
}

// Group prefixes are how two directories that name their groups the same way
// are kept apart.
func TestRefreshMergesBackendsWithPrefixes(t *testing.T) {
	first := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	second := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	firstBackend, secondBackend := testBackend("first"), testBackend("second")
	firstBackend.GroupPrefix = "first:"
	secondBackend.GroupPrefix = "second:"

	d := newTestDirectory(t, testConfig(firstBackend, secondBackend), first, second)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, _ := d.Groups("alice@example.net")
	if !reflect.DeepEqual(groups, []string{"first:admins", "second:admins"}) {
		t.Errorf("expected both prefixed groups, got %v", groups)
	}
}

// Merging only what the reachable backends returned would quietly drop the
// groups a user holds in the unreachable one.
func TestRefreshFailsWhenABackendIsDown(t *testing.T) {
	first := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	second := connWithUsers([]string{"contractors"}, map[string][]string{"alice@example.net": {"contractors"}})

	d := newTestDirectory(t, testConfig(testBackend("first"), testBackend("second")), first, second)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	second.searchErr = errors.New("directory is down")

	err := d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing with a broken backend")
	}
	if !strings.Contains(err.Error(), `backend "second"`) {
		t.Errorf("expected the error to name the broken backend, got %q", err)
	}

	// The previous, complete mapping must still be the one being served.
	groups, ok := d.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins", "contractors"}) {
		t.Errorf("expected the previous merged mapping to be kept, got %v (found=%t)", groups, ok)
	}
}

// A backend whose searches still succeed but find nobody would otherwise merge
// in as a backend that contributes nothing, silently stripping every user of
// that directory of their groups.
func TestRefreshFailsWhenABackendStopsReturningUsers(t *testing.T) {
	first := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	second := connWithUsers([]string{"contractors"}, map[string][]string{"bob@example.net": {"contractors"}})

	d := newTestDirectory(t, testConfig(testBackend("first"), testBackend("second")), first, second)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// What a bind account that has lost its read on the user OU looks like:
	// the search succeeds, it just finds nobody.
	second.entries["OU=Users,DC=example,DC=net"] = nil

	err := d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing with a backend that returned no users")
	}
	if !strings.Contains(err.Error(), `backend "second": returned no users`) {
		t.Errorf("expected the error to name the emptied backend, got %q", err)
	}

	if groups, ok := d.Groups("bob@example.net"); !ok || !reflect.DeepEqual(groups, []string{"contractors"}) {
		t.Errorf("expected the previous mapping to be kept, got %v (found=%t)", groups, ok)
	}
}

// Losing the groups leaves the users in place, each of them with nothing.
func TestRefreshFailsWhenABackendStopsReturningGroups(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	c.entries["OU=Groups,DC=example,DC=net"] = nil

	err := d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing with a backend that returned no groups")
	}
	if !strings.Contains(err.Error(), "returned no groups") {
		t.Errorf("expected the error to say what was empty, got %q", err)
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the previous mapping to be kept, got %v (found=%t)", groups, ok)
	}
}

// A backend that has never returned anything is a configuration to fix, not a
// mapping to protect. Failing on it would leave the proxy unable to start.
func TestRefreshAcceptsABackendThatWasAlwaysEmpty(t *testing.T) {
	d := newTestDirectory(t, testConfig(), &fakeConn{entries: map[string][]*goldap.Entry{}})

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing an empty directory: %s", err)
	}

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing an empty directory again: %s", err)
	}
}

// Users leave, and any threshold short of a collapse to nothing would be a
// guess at how much churn is normal.
func TestRefreshAcceptsABackendThatShrinks(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{
		"alice@example.net": {"admins"},
		"bob@example.net":   {"admins"},
		"carol@example.net": {"admins"},
	})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	c.entries["OU=Users,DC=example,DC=net"] = c.entries["OU=Users,DC=example,DC=net"][:1]

	if err := d.Refresh(); err != nil {
		t.Fatalf("expected a shrinking directory to be accepted, got %s", err)
	}

	if users := d.Stats().Users; users != 1 {
		t.Errorf("expected the smaller mapping to have been swapped in, got %d users", users)
	}
}

// The group and memberOf attributes are not guaranteed to agree on the case or
// spacing of a DN.
func TestRefreshMatchesDNsLoosely(t *testing.T) {
	c := &fakeConn{entries: map[string][]*goldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("CN=admins,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"admins"}}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"alice@example.net"},
				"memberOf":          {"cn=Admins, ou=groups, dc=Example, dc=net"},
			}),
		},
	}}

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, _ := d.Groups("alice@example.net")
	if !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected groups [admins], got %v", groups)
	}
}

// connWithRangedUser returns a fake connection serving one user whose memberOf
// the directory truncates into windows, the way Active Directory does past
// MaxValRange.
func connWithRangedUser(username string, groups []string, window int) *fakeConn {
	c := &fakeConn{entries: map[string][]*goldap.Entry{}}

	dns := make([]string, len(groups))
	for i, group := range groups {
		dns[i] = "CN=" + group + ",OU=Groups,DC=example,DC=net"

		c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"],
			entry(dns[i], map[string][]string{"cn": {group}}))
	}

	userDN := "CN=" + username + ",OU=Users,DC=example,DC=net"

	// chunk is the entry the directory answers with for the values from first
	// onwards, naming the attribute the way it reports the window.
	chunk := func(first int) *goldap.Entry {
		last, name := first+window, fmt.Sprintf("memberOf;range=%d-%d", first, first+window-1)
		if last >= len(dns) {
			last, name = len(dns), fmt.Sprintf("memberOf;range=%d-*", first)
		}

		return &goldap.Entry{DN: userDN, Attributes: []*goldap.EntryAttribute{
			{Name: "userPrincipalName", Values: []string{username}},
			{Name: name, Values: dns[first:last]},
		}}
	}

	c.entries["OU=Users,DC=example,DC=net"] = []*goldap.Entry{chunk(0)}

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
func TestRefreshFollowsARangedMemberOf(t *testing.T) {
	groups := make([]string, 7)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%d", i)
	}

	c := connWithRangedUser("alice@example.net", groups, 3)

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	got, ok := d.Groups("alice@example.net")
	if !ok {
		t.Fatal("expected the user to be found")
	}

	if !reflect.DeepEqual(got, groups) {
		t.Errorf("expected every group of the truncated memberOf, got %v", got)
	}

	// The first window arrives with the user search, so 7 values in windows of
	// 3 leave two to collect.
	if c.searches != 2 {
		t.Errorf("expected 2 follow up searches, got %d", c.searches)
	}
}

// The window has to move, or collecting it would only stop at the request
// bound.
func TestRefreshFailsWhenTheDirectoryDoesNotAdvanceTheRange(t *testing.T) {
	c := connWithRangedUser("alice@example.net", []string{"a", "b", "c", "d"}, 2)

	c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
		return &goldap.SearchResult{Entries: []*goldap.Entry{{
			DN: "CN=alice@example.net,OU=Users,DC=example,DC=net",
			Attributes: []*goldap.EntryAttribute{{
				Name:   "memberOf;range=0-1",
				Values: []string{"CN=a,OU=Groups,DC=example,DC=net"},
			}},
		}}}, nil
	}

	d := newTestDirectory(t, testConfig(), c)

	err := d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing against a directory that never advances the range")
	}

	if !strings.Contains(err.Error(), "did not advance") {
		t.Errorf("expected the error to say the window did not advance, got %q", err)
	}
}

// A directory answers with the attribute descriptions of its own schema rather
// than the ones that were asked for. 389 Directory Server, which FreeIPA is
// built on, is the common case.
func TestRefreshMatchesAttributeNamesCaseInsensitively(t *testing.T) {
	c := &fakeConn{entries: map[string][]*goldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("cn=admins,ou=groups,dc=example,dc=net", map[string][]string{"CN": {"admins"}}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("uid=alice,ou=users,dc=example,dc=net", map[string][]string{
				"UID":      {"alice@example.net"},
				"memberof": {"cn=admins,ou=groups,dc=example,dc=net"},
			}),
		},
	}}

	backend := testBackend("ipa")
	backend.UsernameAttribute = "uid"
	backend.GroupNameAttribute = "cn"

	d := newTestDirectory(t, testConfig(backend), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected groups [admins], got %v (found=%t)", groups, ok)
	}
}

func TestParseRangeOption(t *testing.T) {
	tests := map[string]struct {
		options string
		expNext int
		expErr  bool
	}{
		"no options":          {"", -1, false},
		"an unrelated option": {"binary", -1, false},
		"a truncated range":   {"range=0-1499", 1500, false},
		"a later window":      {"range=1500-2999", 3000, false},
		"the final window":    {"range=3000-*", -1, false},
		"an upper case range": {"RANGE=0-1499", 1500, false},
		"among other options": {"binary;range=0-9", 10, false},
		"no bounds":           {"range=0", 0, true},
		"a non numeric bound": {"range=0-x", 0, true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			next, err := parseRangeOption(test.options)

			if test.expErr {
				if err == nil {
					t.Fatalf("expected an error parsing %q, got none", test.options)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error parsing %q: %s", test.options, err)
			}

			if next != test.expNext {
				t.Errorf("expected the values to continue from %d, got %d", test.expNext, next)
			}
		})
	}
}

func TestRefreshAppliesGroupPrefix(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	backend := testBackend("ldap")
	backend.GroupPrefix = "ldap:"

	d := newTestDirectory(t, testConfig(backend), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, _ := d.Groups("alice@example.net")
	if !reflect.DeepEqual(groups, []string{"ldap:admins"}) {
		t.Errorf("expected groups [ldap:admins], got %v", groups)
	}
}

// The username of a request carries the OIDC username prefix, the directory
// does not.
func TestGroupsStripsUsernamePrefix(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	config := testConfig()
	config.UsernamePrefix = "oidc:"

	d := newTestDirectory(t, config, c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, ok := d.Groups("oidc:alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected groups [admins], got %v (found=%t)", groups, ok)
	}
}

// A failed refresh must leave the previously built mapping serving requests.
func TestFailedRefreshKeepsPreviousMapping(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	c.searchErr = errors.New("directory is down")

	if err := d.Refresh(); err == nil {
		t.Fatal("expected an error refreshing against a broken directory")
	}

	groups, ok := d.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the previous mapping to be kept, got %v (found=%t)", groups, ok)
	}
}

func TestConnectFailsOverBetweenURLs(t *testing.T) {
	config := testConfig()
	config.Backends[0].URLs = []string{"ldaps://down.example.net:636", "ldaps://up.example.net:636"}

	c := &fakeConn{}

	d, err := New(config, nil)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}

	var dialled []string
	d.backends[0].dial = func(url string) (conn, error) {
		dialled = append(dialled, url)
		if url == "ldaps://down.example.net:636" {
			return nil, errors.New("connection refused")
		}
		return c, nil
	}

	got, err := d.backends[0].connect()
	if err != nil {
		t.Fatalf("unexpected error connecting: %s", err)
	}
	if got != conn(c) {
		t.Error("expected the second URL to be used")
	}
	if !reflect.DeepEqual(dialled, config.Backends[0].URLs) {
		t.Errorf("expected both URLs to be dialled in order, got %v", dialled)
	}
}

// Readers must always see a complete mapping, never a partially built one.
func TestConcurrentRefreshAndLookup(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if err := d.Refresh(); err != nil {
					t.Errorf("unexpected error refreshing: %s", err)
					return
				}
			}
		}()

		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if groups, ok := d.Groups("alice@example.net"); !ok || len(groups) != 1 {
					t.Errorf("expected a complete mapping, got %v (found=%t)", groups, ok)
					return
				}
			}
		}()
	}

	wg.Wait()
}

// The mapping is shared by every request, so a caller appending to the groups
// of a user must not be able to write into it.
func TestGroupsCannotBeAppendedTo(t *testing.T) {
	// Merged from two backends, since merging is where spare capacity would
	// otherwise creep into the slices.
	first := connWithUsers([]string{"a", "b"}, map[string][]string{"alice@example.net": {"a", "b"}})
	second := connWithUsers([]string{"c"}, map[string][]string{"alice@example.net": {"c"}})

	d := newTestDirectory(t, testConfig(testBackend("first"), testBackend("second")), first, second)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// Two requests appending to the groups of the same user, as the
	// impersonation handler does with system:authenticated.
	firstGroups, _ := d.Groups("alice@example.net")
	secondGroups, _ := d.Groups("alice@example.net")

	appendedFirst := append(firstGroups, "first")
	appendedSecond := append(secondGroups, "second")

	// Spare capacity in the shared slice would have the second append
	// overwrite the value the first one wrote.
	if got := appendedFirst[len(appendedFirst)-1]; got != "first" {
		t.Errorf("expected the appends to be independent, got %q", got)
	}
	if got := appendedSecond[len(appendedSecond)-1]; got != "second" {
		t.Errorf("expected the appends to be independent, got %q", got)
	}

	after, _ := d.Groups("alice@example.net")
	if !reflect.DeepEqual(after, []string{"a", "b", "c"}) {
		t.Errorf("expected the mapping to be unaffected, got %v", after)
	}
}

func TestCanRefresh(t *testing.T) {
	tests := map[string]struct {
		refreshUsers   []string
		usernamePrefix string

		username string
		exp      bool
	}{
		"no configured users allows anyone": {
			refreshUsers: nil,
			username:     "alice@example.net",
			exp:          true,
		},
		"an empty configured list allows anyone": {
			refreshUsers: []string{},
			username:     "alice@example.net",
			exp:          true,
		},
		"a configured user is allowed": {
			refreshUsers: []string{"alice@example.net", "bob@example.net"},
			username:     "bob@example.net",
			exp:          true,
		},
		"an unconfigured user is not allowed": {
			refreshUsers: []string{"alice@example.net"},
			username:     "eve@example.net",
			exp:          false,
		},
		"matching is case insensitive": {
			refreshUsers: []string{"Alice@Example.net"},
			username:     "alice@example.net",
			exp:          true,
		},
		"a user given without the username prefix is allowed": {
			refreshUsers:   []string{"alice@example.net"},
			usernamePrefix: "oidc:",
			username:       "oidc:alice@example.net",
			exp:            true,
		},
		"a user given with the username prefix is allowed": {
			refreshUsers:   []string{"oidc:alice@example.net"},
			usernamePrefix: "oidc:",
			username:       "oidc:alice@example.net",
			exp:            true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			config.RefreshUsers = test.refreshUsers
			config.UsernamePrefix = test.usernamePrefix

			d, err := New(config, nil)
			if err != nil {
				t.Fatalf("unexpected error building directory: %s", err)
			}

			if got := d.CanRefresh(test.username); got != test.exp {
				t.Errorf("expected CanRefresh(%q)=%t, got %t", test.username, test.exp, got)
			}
		})
	}
}

func TestMergeDeduplicatesGroups(t *testing.T) {
	into := map[string][]string{
		"alice@example.net": {"admins", "shared"},
	}

	merge(into, map[string][]string{
		"alice@example.net": {"shared", "contractors"},
		"bob@example.net":   {"devs"},
	})

	finalise(into)

	exp := map[string][]string{
		"alice@example.net": {"admins", "contractors", "shared"},
		"bob@example.net":   {"devs"},
	}

	if !reflect.DeepEqual(into, exp) {
		t.Errorf("expected merged mapping %v, got %v", exp, into)
	}
}

func TestFinaliseSortsGroups(t *testing.T) {
	mapping := map[string][]string{"alice@example.net": {"c", "a", "b"}}

	finalise(mapping)

	if got := mapping["alice@example.net"]; !sort.StringsAreSorted(got) {
		t.Errorf("expected sorted groups, got %v", got)
	}
}

// memoryStore is a cache.Store that keeps the payload in memory.
type memoryStore struct {
	data []byte

	loadErr error
	saveErr error

	saves int
}

func (m *memoryStore) Load(_ context.Context) ([]byte, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if m.data == nil {
		return nil, cache.ErrNotFound
	}
	return m.data, nil
}

func (m *memoryStore) Save(_ context.Context, data []byte) error {
	m.saves++
	if m.saveErr != nil {
		return m.saveErr
	}
	m.data = data
	return nil
}

func (m *memoryStore) String() string { return "memory" }

func TestRefreshPersistsMapping(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := new(memoryStore)

	d, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if store.saves != 1 {
		t.Fatalf("expected the mapping to have been persisted once, got %d saves", store.saves)
	}

	snapshot := new(Snapshot)
	if err := json.Unmarshal(store.data, snapshot); err != nil {
		t.Fatalf("unexpected error decoding the persisted mapping: %s", err)
	}

	if snapshot.Version != snapshotVersion {
		t.Errorf("expected version %d, got %d", snapshotVersion, snapshot.Version)
	}
	if !reflect.DeepEqual(snapshot.Users, map[string][]string{"alice@example.net": {"admins"}}) {
		t.Errorf("expected the mapping to have been persisted, got %v", snapshot.Users)
	}
	if snapshot.BuiltAt.IsZero() {
		t.Error("expected the persisted mapping to record when it was built")
	}

	if !reflect.DeepEqual(snapshot.Backends, []SnapshotBackend{{Name: "ldap", Users: 1, Groups: 1}}) {
		t.Errorf("expected what each backend contributed to be persisted, got %v", snapshot.Backends)
	}
}

// The guard against an emptied backend has to survive the restart the
// persisted mapping exists for: a proxy coming back up while a directory has
// quietly stopped answering must not accept the degraded mapping, nor persist
// it over the good one.
func TestRunFailsARestoredBackendThatStopsReturningUsers(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := new(memoryStore)

	before, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	before.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := before.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// The directory still answers after the restart, it just finds nobody.
	c.entries["OU=Users,DC=example,DC=net"] = nil

	after, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	after.backends[0].dial = func(string) (conn, error) { return c, nil }

	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := after.Run(stopCh); err != nil {
		t.Fatalf("expected the persisted mapping to keep startup going, got %s", err)
	}

	groups, ok := after.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the persisted mapping to be served, got %v (found=%t)", groups, ok)
	}

	if store.saves != 1 {
		t.Errorf("expected the degraded mapping not to have been persisted, got %d saves", store.saves)
	}
}

// A failure to persist must not fail a refresh that otherwise worked.
func TestRefreshSucceedsWhenPersistingFails(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := &memoryStore{saveErr: errors.New("store is down")}

	d, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := d.Refresh(); err != nil {
		t.Errorf("expected a refresh that could not be persisted to succeed, got %s", err)
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the mapping to be served, got %v (found=%t)", groups, ok)
	}
}

// The point of persisting the mapping: a proxy that comes back up while every
// directory is unreachable still serves the last mapping it built.
func TestRunServesPersistedMappingWhenTheDirectoryIsDown(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := new(memoryStore)

	// The proxy before the restart, which built and persisted a mapping.
	before, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	before.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := before.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// The proxy after the restart, which cannot reach the directory at all.
	after, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	after.backends[0].dial = func(string) (conn, error) { return nil, errors.New("connection refused") }

	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := after.Run(stopCh); err != nil {
		t.Fatalf("expected the persisted mapping to keep startup going, got %s", err)
	}

	groups, ok := after.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the persisted mapping to be served, got %v (found=%t)", groups, ok)
	}

	if stats := after.Stats(); stats.Source != SourceCache {
		t.Errorf("expected the mapping to be sourced from %q, got %q", SourceCache, stats.Source)
	}
}

// The same restart, through the file store rather than a test double, so that
// what is actually written to disk is what is actually read back.
func TestRunServesTheMappingPersistedToAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "mapping.json")

	store, err := cache.NewFile(path)
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	config := testConfig()
	config.Cache = &CacheConfig{Type: CacheTypeFile, File: &FileCacheConfig{Path: path}}

	before, err := New(config, store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	before.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := before.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected the mapping to have been written to disk: %s", err)
	}

	after, err := New(config, store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	after.backends[0].dial = func(string) (conn, error) { return nil, errors.New("connection refused") }

	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := after.Run(stopCh); err != nil {
		t.Fatalf("expected the persisted mapping to keep startup going, got %s", err)
	}

	groups, ok := after.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the mapping written to disk to be served, got %v (found=%t)", groups, ok)
	}
}

// With nothing persisted to fall back on, a proxy that cannot build a mapping
// must not start: serving an empty mapping strips every user of their groups.
func TestRunFailsWithNoMappingToFallBackOn(t *testing.T) {
	d, err := New(testConfig(), new(memoryStore))
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return nil, errors.New("connection refused") }

	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := d.Run(stopCh); err == nil {
		t.Fatal("expected startup to fail with no mapping to fall back on")
	}
}

// A directory that is reachable at startup must win over what was persisted.
func TestRunPrefersTheDirectoryOverThePersistedMapping(t *testing.T) {
	store := new(memoryStore)

	stale := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	before, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	before.backends[0].dial = func(string) (conn, error) { return stale, nil }

	if err := before.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// Alice has since been moved out of the admins group.
	current := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {}})

	after, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	after.backends[0].dial = func(string) (conn, error) { return current, nil }

	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := after.Run(stopCh); err != nil {
		t.Fatalf("unexpected error running: %s", err)
	}

	if groups, _ := after.Groups("alice@example.net"); len(groups) != 0 {
		t.Errorf("expected the mapping from the directory to win, got %v", groups)
	}

	if stats := after.Stats(); stats.Source != SourceDirectory {
		t.Errorf("expected the mapping to be sourced from %q, got %q", SourceDirectory, stats.Source)
	}
}

func TestRestoreRejectsUnusableSnapshots(t *testing.T) {
	config := testConfig()

	d, err := New(config, nil)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}

	good := Snapshot{
		Version:     snapshotVersion,
		MappingHash: config.mappingHash(),
		BuiltAt:     time.Now(),
		Users:       map[string][]string{"alice@example.net": {"admins"}},
	}

	otherConfig := testConfig()
	otherConfig.Backends[0].GroupSearchBases = []string{"OU=Other,DC=example,DC=net"}

	tests := map[string]struct {
		mutate func(*Snapshot)
		maxAge time.Duration
		expErr string
	}{
		"a snapshot of another version": {
			mutate: func(s *Snapshot) { s.Version = snapshotVersion + 1 },
			expErr: "version",
		},
		"a snapshot of another configuration": {
			mutate: func(s *Snapshot) { s.MappingHash = otherConfig.mappingHash() },
			expErr: "different backend configuration",
		},
		"a snapshot with no users": {
			mutate: func(s *Snapshot) { s.Users = nil },
			expErr: "holds no users",
		},
		"a snapshot older than the configured maximum age": {
			mutate: func(s *Snapshot) { s.BuiltAt = time.Now().Add(-time.Hour) },
			maxAge: time.Minute,
			expErr: "maxAge",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			snapshot := good
			test.mutate(&snapshot)

			data, err := json.Marshal(&snapshot)
			if err != nil {
				t.Fatalf("unexpected error encoding snapshot: %s", err)
			}

			d.config.Cache = &CacheConfig{Type: CacheTypeNone, MaxAge: Duration(test.maxAge)}

			if _, err := d.decodeSnapshot(data); err == nil {
				t.Errorf("expected an error containing %q, got none", test.expErr)
			} else if !strings.Contains(err.Error(), test.expErr) {
				t.Errorf("expected an error containing %q, got %q", test.expErr, err)
			}
		})
	}

	// The unmutated snapshot must still be accepted, so that the cases above
	// are failing for the reason they claim.
	d.config.Cache = nil

	data, err := json.Marshal(&good)
	if err != nil {
		t.Fatalf("unexpected error encoding snapshot: %s", err)
	}

	if _, err := d.decodeSnapshot(data); err != nil {
		t.Errorf("expected a good snapshot to be accepted, got %s", err)
	}
}

// A mapping built from a directory whose layout has since been reconfigured
// describes groups the proxy is no longer meant to hand out.
func TestMappingHashCoversTheLayoutOfTheBackends(t *testing.T) {
	base := testConfig()

	tests := map[string]struct {
		mutate    func(*Config)
		expChange bool
	}{
		"a changed group search base": {
			func(c *Config) { c.Backends[0].GroupSearchBases = []string{"OU=Other,DC=example,DC=net"} }, true,
		},
		"a changed group prefix":  {func(c *Config) { c.Backends[0].GroupPrefix = "ldap:" }, true},
		"a changed user filter":   {func(c *Config) { c.Backends[0].UserFilter = "(objectClass=person)" }, true},
		"an added backend":        {func(c *Config) { c.Backends = append(c.Backends, testBackend("second")) }, true},
		"a rotated password":      {func(c *Config) { c.Backends[0].BindPassword = "rotated" }, false},
		"a changed url":           {func(c *Config) { c.Backends[0].URLs = []string{"ldaps://other.example.net:636"} }, false},
		"a changed refresh":       {func(c *Config) { c.RefreshInterval = NewDuration(time.Hour) }, false},
		"a changed cache setting": {func(c *Config) { c.Cache = &CacheConfig{Type: CacheTypeNone} }, false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			test.mutate(config)

			if changed := config.mappingHash() != base.mappingHash(); changed != test.expChange {
				t.Errorf("expected the hash to change=%t, got %t", test.expChange, changed)
			}
		})
	}
}
