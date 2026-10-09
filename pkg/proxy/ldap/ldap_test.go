// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
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
		dn := "CN=" + group + ",OU=Groups,DC=example,DC=net"
		c.entries[dn] = []*goldap.Entry{entry(dn, map[string][]string{"cn": {group}})}
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
		"no backends":                    {func(c *Config) { c.Backends = nil }, "at least one backend must be configured"},
		"no name":                        {func(c *Config) { c.Backends[0].Name = "" }, "name must be set"},
		"no URL":                         {func(c *Config) { c.Backends[0].URLs = nil }, "at least one url must be set"},
		"no user search base":            {func(c *Config) { c.Backends[0].UserSearchBases = nil }, "at least one userSearchBase must be set"},
		"no group search base":           {func(c *Config) { c.Backends[0].GroupSearchBases = nil }, "at least one groupSearchBase must be set"},
		"a zero refresh interval":        {func(c *Config) { c.RefreshInterval = NewDuration(0) }, "refreshInterval must be a positive duration"},
		"a negative refresh concurrency": {func(c *Config) { c.RefreshConcurrency = -1 }, "refreshConcurrency must be positive"},
		"duplicate names": {
			func(c *Config) { c.Backends = append(c.Backends, testBackend("ldap")) },
			"duplicate backend name",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			test.mutate(config)

			_, err := newResolver(config)
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", test.expErr)
			}

			if !strings.Contains(err.Error(), test.expErr) {
				t.Errorf("expected an error containing %q, got %q", test.expErr, err)
			}
		})
	}
}

func TestEachBackendReturnsFirstErrorInConfigOrder(t *testing.T) {
	backends := []*backend{
		{config: &BackendConfig{Name: "a"}},
		{config: &BackendConfig{Name: "b"}},
		{config: &BackendConfig{Name: "c"}},
	}

	results, err := eachBackend(backends, func(b *backend) (string, error) {
		if b.config.Name != "a" {
			return "", errors.New("failed")
		}
		return b.config.Name, nil
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), `backend "b"`) {
		t.Errorf("expected the first error in configuration order, got %q", err)
	}
	if results != nil {
		t.Errorf("expected no results when a backend failed, got %v", results)
	}

	names, err := eachBackend(backends, func(b *backend) (string, error) {
		return b.config.Name, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if exp := []string{"a", "b", "c"}; !reflect.DeepEqual(names, exp) {
		t.Errorf("expected results in configuration order, exp=%v got=%v", exp, names)
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

func TestConnectFailsOverBetweenURLs(t *testing.T) {
	config := testConfig()
	config.Backends[0].URLs = []string{"ldaps://down.example.net:636", "ldaps://up.example.net:636"}

	c := &fakeConn{}

	d, err := newResolver(config)
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

	got, cleanup, err := d.backends[0].connect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error connecting: %s", err)
	}
	defer cleanup()
	if got != conn(c) {
		t.Error("expected the second URL to be used")
	}
	if !reflect.DeepEqual(dialled, config.Backends[0].URLs) {
		t.Errorf("expected both URLs to be dialled in order, got %v", dialled)
	}
}

func TestConnectSetsTheStartTLSServerName(t *testing.T) {
	config := testConfig()
	config.Backends[0].URLs = []string{"ldap://ldap.example.net:389"}
	config.Backends[0].StartTLS = true

	c := &fakeConn{}
	d := newTestResolver(t, config, c)

	_, cleanup, err := d.backends[0].connect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error connecting: %s", err)
	}
	defer cleanup()

	if c.startTLSConfig == nil {
		t.Fatal("expected StartTLS to be called")
	}
	if got := c.startTLSConfig.ServerName; got != "ldap.example.net" {
		t.Errorf("expected StartTLS to verify ldap.example.net, got %q", got)
	}
	if d.backends[0].tlsConfig.ServerName != "" {
		t.Errorf("expected the shared TLS config not to be mutated, got server name %q",
			d.backends[0].tlsConfig.ServerName)
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
		"a prefixed allowed user does not authorize a raw name beginning with the prefix": {
			refreshUsers:   []string{"oidc:alice@example.net"},
			usernamePrefix: "oidc:",
			username:       "oidc:oidc:alice@example.net",
			exp:            false,
		},
		"a raw name beginning with the prefix can be allowed by its full token name": {
			refreshUsers:   []string{"oidc:oidc:alice@example.net"},
			usernamePrefix: "oidc:",
			username:       "oidc:oidc:alice@example.net",
			exp:            true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			config.RefreshUsers = test.refreshUsers
			config.UsernamePrefix = test.usernamePrefix

			d, err := newResolver(config)
			if err != nil {
				t.Fatalf("unexpected error building directory: %s", err)
			}

			if got := d.CanRefresh(test.username); got != test.exp {
				t.Errorf("expected CanRefresh(%q)=%t, got %t", test.username, test.exp, got)
			}
		})
	}
}

func TestSearchFingerprintCoversBackendLayout(t *testing.T) {
	base := testConfig()

	tests := map[string]struct {
		mutate    func(*Config)
		expChange bool
	}{
		"a changed group search base": {
			func(c *Config) { c.Backends[0].GroupSearchBases = []string{"OU=Other,DC=example,DC=net"} }, true,
		},
		"a changed user filter":   {func(c *Config) { c.Backends[0].UserFilter = "(objectClass=person)" }, true},
		"an added backend":        {func(c *Config) { c.Backends = append(c.Backends, testBackend("second")) }, true},
		"a rotated password":      {func(c *Config) { c.Backends[0].BindPassword = "rotated" }, false},
		"a changed url":           {func(c *Config) { c.Backends[0].URLs = []string{"ldaps://other.example.net:636"} }, true},
		"a changed bind DN":       {func(c *Config) { c.Backends[0].BindDN = "CN=Other,DC=example,DC=net" }, true},
		"a changed refresh":       {func(c *Config) { c.RefreshInterval = NewDuration(time.Hour) }, false},
		"a changed cache setting": {func(c *Config) { c.Cache = &CacheConfig{Namespace: "other"} }, false},
		"a changed timeout":       {func(c *Config) { c.Backends[0].Timeout = NewDuration(time.Hour) }, false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			test.mutate(config)

			if changed := config.searchFingerprint() != base.searchFingerprint(); changed != test.expChange {
				t.Errorf("expected the hash to change=%t, got %t", test.expChange, changed)
			}
		})
	}
}

type hangingConn struct {
	*fakeConn

	closed chan struct{}
	once   sync.Once
}

func newHangingConn() *hangingConn {
	return &hangingConn{
		fakeConn: &fakeConn{entries: map[string][]*goldap.Entry{}},
		closed:   make(chan struct{}),
	}
}

func (h *hangingConn) Close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}
