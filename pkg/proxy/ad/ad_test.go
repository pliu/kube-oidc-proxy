// Copyright Jetstack Ltd. See LICENSE for details.
package ad

import (
	"crypto/tls"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type fakeConn struct {
	// entries maps a search base to the entries returned for it.
	entries map[string][]*ldap.Entry

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

func (f *fakeConn) SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return &ldap.SearchResult{Entries: f.entries[req.BaseDN]}, nil
}

func (f *fakeConn) Close() error {
	f.closed = true
	return nil
}

func entry(dn string, attrs map[string][]string) *ldap.Entry {
	e := &ldap.Entry{DN: dn}
	for name, values := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: name, Values: values})
	}
	return e
}

func testConfig() *Config {
	return &Config{
		URLs:               []string{"ldaps://ad.example.net:636"},
		BindDN:             "CN=svc,DC=example,DC=net",
		BindPassword:       "password",
		UserSearchBases:    []string{"OU=Users,DC=example,DC=net"},
		UserFilter:         "(objectClass=user)",
		UsernameAttribute:  "userPrincipalName",
		GroupSearchBases:   []string{"OU=Groups,DC=example,DC=net"},
		GroupFilter:        "(objectClass=group)",
		GroupNameAttribute: "cn",
		RefreshInterval:    time.Minute * 10,
	}
}

// newTestDirectory returns a Directory that searches the given fake connection
// rather than a real server.
func newTestDirectory(t *testing.T, config *Config, c conn) *Directory {
	t.Helper()

	d, err := New(config)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}

	d.dial = func(string) (conn, error) { return c, nil }

	return d
}

func TestNewValidatesConfig(t *testing.T) {
	tests := map[string]struct {
		mutate   func(*Config)
		expError error
	}{
		"no URL":               {func(c *Config) { c.URLs = nil }, ErrNoURL},
		"no user search base":  {func(c *Config) { c.UserSearchBases = nil }, ErrNoUserSearchBase},
		"no group search base": {func(c *Config) { c.GroupSearchBases = nil }, ErrNoGroupSearchBase},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			test.mutate(config)

			if _, err := New(config); !errors.Is(err, test.expError) {
				t.Errorf("expected error %v, got %v", test.expError, err)
			}
		})
	}
}

func TestRefreshBuildsMapping(t *testing.T) {
	c := &fakeConn{entries: map[string][]*ldap.Entry{
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

			sort.Strings(groups)
			if !reflect.DeepEqual(groups, test.expGroups) {
				t.Errorf("expected groups %v, got %v", test.expGroups, groups)
			}
		})
	}

	if stats := d.Stats(); stats.Users != 2 || stats.Groups != 2 {
		t.Errorf("expected stats of 2 users and 2 groups, got %d and %d", stats.Users, stats.Groups)
	}
}

// The group and memberOf attributes are not guaranteed to agree on the case or
// spacing of a DN.
func TestRefreshMatchesDNsLoosely(t *testing.T) {
	c := &fakeConn{entries: map[string][]*ldap.Entry{
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

func TestRefreshAppliesGroupPrefix(t *testing.T) {
	c := &fakeConn{entries: map[string][]*ldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("CN=admins,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"admins"}}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"alice@example.net"},
				"memberOf":          {"CN=admins,OU=Groups,DC=example,DC=net"},
			}),
		},
	}}

	config := testConfig()
	config.GroupPrefix = "ad:"

	d := newTestDirectory(t, config, c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, _ := d.Groups("alice@example.net")
	if !reflect.DeepEqual(groups, []string{"ad:admins"}) {
		t.Errorf("expected groups [ad:admins], got %v", groups)
	}
}

// The username of a request carries the OIDC username prefix, the directory
// does not.
func TestGroupsStripsUsernamePrefix(t *testing.T) {
	c := &fakeConn{entries: map[string][]*ldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("CN=admins,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"admins"}}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"alice@example.net"},
				"memberOf":          {"CN=admins,OU=Groups,DC=example,DC=net"},
			}),
		},
	}}

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
	c := &fakeConn{entries: map[string][]*ldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("CN=admins,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"admins"}}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"alice@example.net"},
				"memberOf":          {"CN=admins,OU=Groups,DC=example,DC=net"},
			}),
		},
	}}

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
	config.URLs = []string{"ldaps://down.example.net:636", "ldaps://up.example.net:636"}

	c := &fakeConn{}

	d, err := New(config)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}

	var dialled []string
	d.dial = func(url string) (conn, error) {
		dialled = append(dialled, url)
		if url == "ldaps://down.example.net:636" {
			return nil, errors.New("connection refused")
		}
		return c, nil
	}

	got, err := d.connect()
	if err != nil {
		t.Fatalf("unexpected error connecting: %s", err)
	}
	if got != conn(c) {
		t.Error("expected the second URL to be used")
	}
	if !reflect.DeepEqual(dialled, config.URLs) {
		t.Errorf("expected both URLs to be dialled in order, got %v", dialled)
	}
}

// Readers must always see a complete mapping, never a partially built one.
func TestConcurrentRefreshAndLookup(t *testing.T) {
	c := &fakeConn{entries: map[string][]*ldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("CN=admins,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"admins"}}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"alice@example.net"},
				"memberOf":          {"CN=admins,OU=Groups,DC=example,DC=net"},
			}),
		},
	}}

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
	c := &fakeConn{entries: map[string][]*ldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("CN=a,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"a"}}),
			entry("CN=b,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"b"}}),
			entry("CN=c,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"c"}}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"alice@example.net"},
				"memberOf": {
					"CN=a,OU=Groups,DC=example,DC=net",
					"CN=b,OU=Groups,DC=example,DC=net",
					"CN=c,OU=Groups,DC=example,DC=net",
				},
			}),
		},
	}}

	d := newTestDirectory(t, testConfig(), c)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// Two requests appending to the groups of the same user, as the
	// impersonation handler does with system:authenticated.
	first, _ := d.Groups("alice@example.net")
	second, _ := d.Groups("alice@example.net")

	firstGroups := append(first, "first")
	secondGroups := append(second, "second")

	// Spare capacity in the shared slice would have the second append
	// overwrite the value the first one wrote.
	if got := firstGroups[len(firstGroups)-1]; got != "first" {
		t.Errorf("expected the appends to be independent, got %q", got)
	}
	if got := secondGroups[len(secondGroups)-1]; got != "second" {
		t.Errorf("expected the appends to be independent, got %q", got)
	}

	after, _ := d.Groups("alice@example.net")
	sort.Strings(after)
	if !reflect.DeepEqual(after, []string{"a", "b", "c"}) {
		t.Errorf("expected the mapping to be unaffected, got %v", after)
	}
}
