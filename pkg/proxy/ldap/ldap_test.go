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
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

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

	searchErr      error
	bindErr        error
	startTLSErr    error
	startTLSConfig *tls.Config

	bound  bool
	closed bool
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

// LDAP DNs distinguish these entries, but Kubernetes RBAC sees only the
// emitted name. Accepting both would collapse separate directory groups into
// one authorization identity.
func TestRefreshFailsWhenGroupsShareAnAuthorizationName(t *testing.T) {
	c := &fakeConn{entries: map[string][]*goldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry("CN=admins,OU=Internal,DC=example,DC=net", map[string][]string{"cn": {"admins"}}),
			entry("CN=admins,OU=External,DC=example,DC=net", map[string][]string{"cn": {"admins"}}),
		},
	}}

	d := newTestDirectory(t, testConfig(), c)

	err := d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing a backend with duplicate group names")
	}

	for _, want := range []string{"admins", "OU=Internal", "OU=External", "authorization identity is ambiguous"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected the error to contain %q, got %q", want, err)
		}
	}
}

// Overlapping search bases can return one entry more than once. That is one
// LDAP group and therefore one authorization identity, not a collision.
func TestRefreshAcceptsOneGroupReturnedByOverlappingSearchBases(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	c.entries["DC=example,DC=net"] = c.entries["OU=Groups,DC=example,DC=net"]

	backend := testBackend("ldap")
	backend.GroupSearchBases = []string{"OU=Groups,DC=example,DC=net", "DC=example,DC=net"}

	d := newTestDirectory(t, testConfig(backend), c)
	if err := d.Refresh(); err != nil {
		t.Fatalf("expected one group returned twice to be accepted, got %s", err)
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected groups [admins], got %v (found=%t)", groups, ok)
	}
}

func TestRefreshDeduplicatesRepeatedMemberOfValues(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	user := c.entries["OU=Users,DC=example,DC=net"][0]
	for _, attribute := range user.Attributes {
		if strings.EqualFold(attribute.Name, memberOfAttribute) {
			attribute.Values = append(attribute.Values, attribute.Values[0])
		}
	}

	d := newTestDirectory(t, testConfig(), c)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected one admins group, got %v (found=%t)", groups, ok)
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

// Which entry a request should be authorized as is genuinely ambiguous, and
// picking whichever came back last would make a user's groups depend on the
// order the directory happened to return them in.
func TestRefreshFailsWhenTwoEntriesClaimOneUsername(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	// A second object holding the same userPrincipalName, in another OU: a
	// recreated account, or one migrated without the old object being removed.
	c.entries["OU=Users,DC=example,DC=net"] = append(c.entries["OU=Users,DC=example,DC=net"],
		entry("CN=alice.old,OU=Contractors,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"alice@example.net"},
		}))

	d := newTestDirectory(t, testConfig(), c)

	err := d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing a directory holding one username twice")
	}

	for _, want := range []string{"alice@example.net", "OU=Users,DC=example,DC=net", "CN=alice.old,OU=Contractors"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected the error to name %q, got %q", want, err)
		}
	}
}

// Search bases that overlap return one entry more than once, which says
// nothing about the identity being ambiguous.
func TestRefreshAcceptsOneEntryReturnedByOverlappingSearchBases(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	// The same entries, reachable under a base that contains the first.
	c.entries["DC=example,DC=net"] = c.entries["OU=Users,DC=example,DC=net"]

	backend := testBackend("ldap")
	backend.UserSearchBases = []string{"OU=Users,DC=example,DC=net", "DC=example,DC=net"}

	d := newTestDirectory(t, testConfig(backend), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("expected overlapping search bases to be accepted, got %s", err)
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected groups [admins], got %v (found=%t)", groups, ok)
	}
}

// A rebuild that fails is not an outage, so nothing about serving a request
// says the mapping has stopped being updated. The gauge is what does.
func TestLastRefreshSuccessGauge(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if got := testutil.ToFloat64(lastRefreshSuccess); got != 1 {
		t.Errorf("expected a successful refresh to report 1, got %v", got)
	}

	c.searchErr = errors.New("directory is down")

	if err := d.Refresh(); err == nil {
		t.Fatal("expected an error refreshing against a broken directory")
	}

	if got := testutil.ToFloat64(lastRefreshSuccess); got != 0 {
		t.Errorf("expected a failed refresh to report 0, got %v", got)
	}

	// Recovering has to clear it again, or it would need a restart to.
	c.searchErr = nil

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if got := testutil.ToFloat64(lastRefreshSuccess); got != 1 {
		t.Errorf("expected a recovered refresh to report 1, got %v", got)
	}
}

// A directory holding one username twice needs somebody to go and clean it up,
// which is worth telling apart from a directory that is merely unreachable.
func TestBackendDuplicateUsersGauge(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(testBackend("corp")), c)

	gauge := backendDuplicateValues.WithLabelValues("corp", duplicateKindUser)
	groupGauge := backendDuplicateValues.WithLabelValues("corp", duplicateKindGroup)

	// The series exists from the start, so that "no duplicates" is a zero
	// rather than an absence.
	if got := testutil.ToFloat64(gauge); got != 0 {
		t.Errorf("expected a backend with no duplicates to report 0, got %v", got)
	}

	duplicate := entry("CN=alice.old,OU=Contractors,DC=example,DC=net", map[string][]string{
		"userPrincipalName": {"alice@example.net"},
	})
	c.entries["OU=Users,DC=example,DC=net"] = append(c.entries["OU=Users,DC=example,DC=net"], duplicate)

	if err := d.Refresh(); err == nil {
		t.Fatal("expected an error refreshing a directory holding one username twice")
	}

	if got := testutil.ToFloat64(gauge); got != 1 {
		t.Errorf("expected a backend holding one username twice to report 1, got %v", got)
	}
	if got := testutil.ToFloat64(groupGauge); got != 0 {
		t.Errorf("expected duplicate users not to set the group series, got %v", got)
	}

	// An unreachable directory says nothing about whether it holds duplicates,
	// so the gauge must stay where it was rather than being cleared.
	c.searchErr = errors.New("directory is down")

	if err := d.Refresh(); err == nil {
		t.Fatal("expected an error refreshing against a broken directory")
	}

	if got := testutil.ToFloat64(gauge); got != 1 {
		t.Errorf("expected an unreachable backend to leave the gauge alone, got %v", got)
	}

	// Cleaning up the directory clears it.
	c.searchErr = nil
	c.entries["OU=Users,DC=example,DC=net"] = c.entries["OU=Users,DC=example,DC=net"][:1]

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if got := testutil.ToFloat64(gauge); got != 0 {
		t.Errorf("expected a cleaned up backend to report 0, got %v", got)
	}
}

// Distinct LDAP groups with one emitted name collapse into one Kubernetes RBAC
// identity, and need the same durable signal as duplicate usernames.
func TestBackendDuplicateGroupsGauge(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	d := newTestDirectory(t, testConfig(testBackend("groups-corp")), c)

	gauge := backendDuplicateValues.WithLabelValues("groups-corp", duplicateKindGroup)
	userGauge := backendDuplicateValues.WithLabelValues("groups-corp", duplicateKindUser)
	if got := testutil.ToFloat64(gauge); got != 0 {
		t.Errorf("expected a backend with no duplicate groups to report 0, got %v", got)
	}

	c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"],
		entry("CN=other-admins,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"admins"}}))

	if err := d.Refresh(); err == nil {
		t.Fatal("expected an error refreshing a directory with duplicate emitted group names")
	}
	if got := testutil.ToFloat64(gauge); got != 1 {
		t.Errorf("expected duplicate groups to report 1, got %v", got)
	}
	if got := testutil.ToFloat64(userGauge); got != 0 {
		t.Errorf("expected duplicate groups not to set the user series, got %v", got)
	}

	// A failed search cannot establish that the duplicate was removed.
	c.searchErr = errors.New("directory is down")
	if err := d.Refresh(); err == nil {
		t.Fatal("expected an error refreshing against a broken directory")
	}
	if got := testutil.ToFloat64(gauge); got != 1 {
		t.Errorf("expected an unreachable backend to leave the group gauge alone, got %v", got)
	}

	c.searchErr = nil
	c.entries["OU=Groups,DC=example,DC=net"] = c.entries["OU=Groups,DC=example,DC=net"][:1]
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing the cleaned up directory: %s", err)
	}
	if got := testutil.ToFloat64(gauge); got != 0 {
		t.Errorf("expected cleaned up duplicate groups to report 0, got %v", got)
	}
}

// histogramCount is the number of observations a histogram holds, which is
// what says whether a rebuild was actually timed rather than merely published.
func histogramCount(t *testing.T, collector prometheus.Collector) uint64 {
	t.Helper()

	metrics := make(chan prometheus.Metric, 32)
	collector.Collect(metrics)
	close(metrics)

	var total uint64
	for metric := range metrics {
		var written dto.Metric
		if err := metric.Write(&written); err != nil {
			t.Fatalf("unexpected error reading a metric: %s", err)
		}

		total += written.GetHistogram().GetSampleCount()
	}

	return total
}

// backendDuration is one backend's timing histogram as a collector: a child of
// a vector is handed back as an Observer, which cannot be collected from.
func backendDuration(t *testing.T, backend string) prometheus.Collector {
	t.Helper()

	collector, ok := backendRefreshDuration.WithLabelValues(backend).(prometheus.Collector)
	if !ok {
		t.Fatal("expected a histogram child to be collectable")
	}

	return collector
}

func TestRefreshDurationsAreObserved(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	second := connWithUsers([]string{"contractors"}, map[string][]string{"bob@example.net": {"contractors"}})

	d := newTestDirectory(t, testConfig(testBackend("first"), testBackend("second")), c, second)

	before := histogramCount(t, refreshDuration)
	beforeFirst := histogramCount(t, backendDuration(t, "first"))
	beforeSecond := histogramCount(t, backendDuration(t, "second"))

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if got := histogramCount(t, refreshDuration) - before; got != 1 {
		t.Errorf("expected the complete rebuild to have been timed once, got %d", got)
	}

	// Each backend is timed separately, so that one slow directory can be told
	// from a rebuild that is slow all over.
	if got := histogramCount(t, backendDuration(t, "first")) - beforeFirst; got != 1 {
		t.Errorf("expected backend \"first\" to have been timed once, got %d", got)
	}
	if got := histogramCount(t, backendDuration(t, "second")) - beforeSecond; got != 1 {
		t.Errorf("expected backend \"second\" to have been timed once, got %d", got)
	}
}

// How long it took to give up says nothing about how long the work takes, and
// would drag the distribution somewhere useless.
func TestFailedRefreshesAreNotTimed(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	c.searchErr = errors.New("directory is down")

	d := newTestDirectory(t, testConfig(testBackend("broken")), c)

	before := histogramCount(t, refreshDuration)
	beforeBackend := histogramCount(t, backendDuration(t, "broken"))

	if err := d.Refresh(); err == nil {
		t.Fatal("expected an error refreshing against a broken directory")
	}

	if got := histogramCount(t, refreshDuration) - before; got != 0 {
		t.Errorf("expected a failed rebuild not to be timed, got %d observations", got)
	}
	if got := histogramCount(t, backendDuration(t, "broken")) - beforeBackend; got != 0 {
		t.Errorf("expected a failed backend not to be timed, got %d observations", got)
	}
}

// gatedConn holds up a rebuild until it is released, so that callers can be
// made to arrive while one is genuinely in flight.
type gatedConn struct {
	*fakeConn

	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func TestRefreshSearchesBackendsConcurrently(t *testing.T) {
	first := &gatedConn{
		fakeConn: connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}}),
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	second := &gatedConn{
		fakeConn: connWithUsers([]string{"devs"}, map[string][]string{"bob@example.net": {"devs"}}),
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	released := false
	defer func() {
		if !released {
			close(first.release)
			close(second.release)
		}
	}()

	d := newTestDirectory(t, testConfig(testBackend("first-parallel"), testBackend("second-parallel")),
		first, second)

	done := make(chan error, 1)
	go func() { done <- d.Refresh() }()

	for name, entered := range map[string]<-chan struct{}{
		"first":  first.entered,
		"second": second.entered,
	} {
		select {
		case <-entered:
		case <-time.After(time.Second * 5):
			t.Fatalf("expected the %s backend to start before either backend was released", name)
		}
	}

	close(first.release)
	close(second.release)
	released = true

	if err := <-done; err != nil {
		t.Fatalf("unexpected error refreshing parallel backends: %s", err)
	}
}

func (g *gatedConn) SearchWithPaging(req *goldap.SearchRequest, size uint32) (*goldap.SearchResult, error) {
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})

	return g.fakeConn.SearchWithPaging(req, size)
}

// A burst of requests to the refresh endpoint must cost one rebuild, not one
// each: every one of them searches every directory in full, and by default any
// authenticated user may ask for one.
func TestConcurrentRefreshesAreCoalesced(t *testing.T) {
	c := &gatedConn{
		fakeConn: connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}}),
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}

	d := newTestDirectory(t, testConfig(), c)

	// One dial per rebuild, so this counts the rebuilds that were actually run.
	var dials atomic.Int32
	d.backends[0].dial = func(string) (conn, error) {
		dials.Add(1)
		return c, nil
	}

	const callers = 8

	var wg sync.WaitGroup
	errs := make([]error, callers)

	wg.Add(1)
	go func() {
		defer wg.Done()
		errs[0] = d.Refresh()
	}()

	// The first caller now holds the rebuild, blocked in the directory.
	<-c.entered

	arrived := make(chan struct{}, callers)
	for i := 1; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			arrived <- struct{}{}
			errs[i] = d.Refresh()
		}(i)
	}

	for i := 1; i < callers; i++ {
		<-arrived
	}

	// Every joiner has been scheduled; give them a moment to actually reach
	// the lock before the rebuild they are meant to join completes.
	time.Sleep(time.Millisecond * 50)

	close(c.release)
	wg.Wait()

	if got := dials.Load(); got != 1 {
		t.Errorf("expected %d concurrent refreshes to cost one rebuild, got %d", callers, got)
	}

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: unexpected error refreshing: %s", i, err)
		}
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the mapping to have been built, got %v (found=%t)", groups, ok)
	}
}

// A joined rebuild reports to its callers what it actually did.
func TestCoalescedRefreshesShareTheFailure(t *testing.T) {
	c := &gatedConn{
		fakeConn: connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}}),
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	c.fakeConn.searchErr = errors.New("directory is down")

	d := newTestDirectory(t, testConfig(), c)

	var wg sync.WaitGroup
	errs := make([]error, 4)

	wg.Add(1)
	go func() {
		defer wg.Done()
		errs[0] = d.Refresh()
	}()

	<-c.entered

	arrived := make(chan struct{}, 3)
	for i := 1; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			arrived <- struct{}{}
			errs[i] = d.Refresh()
		}(i)
	}

	for i := 1; i < 4; i++ {
		<-arrived
	}
	time.Sleep(time.Millisecond * 50)

	close(c.release)
	wg.Wait()

	for i, err := range errs {
		if err == nil {
			t.Errorf("caller %d: expected the failure of the rebuild it joined, got none", i)
		}
	}
}

// A caller arriving once a rebuild is over must get a rebuild, not the result
// of the one that just finished.
func TestRefreshAfterAnotherFinishesRebuilds(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)

	var dials atomic.Int32
	d.backends[0].dial = func(string) (conn, error) {
		dials.Add(1)
		return c, nil
	}

	for i := 0; i < 3; i++ {
		if err := d.Refresh(); err != nil {
			t.Fatalf("unexpected error refreshing: %s", err)
		}
	}

	if got := dials.Load(); got != 3 {
		t.Errorf("expected 3 sequential refreshes to cost 3 rebuilds, got %d", got)
	}
}

// hangingConn accepts a connection and then answers nothing until it is
// closed, the way a directory that has stopped responding does: go-ldap waits
// on a channel that only the connection closing ever unblocks.
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

func (h *hangingConn) SearchWithPaging(*goldap.SearchRequest, uint32) (*goldap.SearchResult, error) {
	<-h.closed
	return nil, errors.New("ldap: response channel closed")
}

func (h *hangingConn) Close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}

// A directory that accepts a connection and then goes quiet has to fail the
// rebuild like any other unreachable backend, rather than holding the refresh
// open for as long as the process runs.
func TestRefreshTimesOutOnABackendThatStopsResponding(t *testing.T) {
	responsive := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := new(memoryStore)

	config := testConfig()
	config.Backends[0].Timeout = NewDuration(time.Millisecond * 50)

	d, err := New(config, store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return responsive, nil }

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}
	if store.saves != 1 {
		t.Fatalf("expected the first mapping to have been persisted, got %d saves", store.saves)
	}

	hanging := newHangingConn()
	d.backends[0].dial = func(string) (conn, error) { return hanging, nil }

	err = d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing against a directory that stopped responding")
	}

	if !strings.Contains(err.Error(), "timed out after 50ms") {
		t.Errorf("expected the error to report the timeout, got %q", err)
	}

	// The connection has to actually be closed, since that is the only thing
	// that unblocks the search waiting on it.
	select {
	case <-hanging.closed:
	default:
		t.Error("expected the timed out connection to have been closed")
	}

	// A timeout is a failed refresh, so the previous mapping keeps serving and
	// nothing is written over the persisted copy of it.
	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the previous mapping to be kept, got %v (found=%t)", groups, ok)
	}

	if store.saves != 1 {
		t.Errorf("expected the timed out refresh not to have been persisted, got %d saves", store.saves)
	}
}

func TestWatchdogClosesAConnectionThatOutlastsIt(t *testing.T) {
	c := newHangingConn()

	w := newWatchdog(time.Millisecond)
	defer w.stop()

	w.watch(c)

	select {
	case <-c.closed:
	case <-time.After(time.Second * 5):
		t.Fatal("expected the watchdog to close the connection it was given")
	}
}

// Dialling races the timeout, so a connection that arrives after it expired
// must not be left open and searched.
func TestWatchdogClosesAConnectionHandedOverAfterItFired(t *testing.T) {
	w := newWatchdog(time.Hour)
	defer w.stop()

	w.fire()

	c := newHangingConn()
	w.watch(c)

	select {
	case <-c.closed:
	default:
		t.Error("expected a connection handed over after the timeout to be closed straight away")
	}

	if err := w.wrap(errors.New("response channel closed")); !strings.Contains(err.Error(), "timed out after 1h0m0s") {
		t.Errorf("expected the error to be reported as the timeout, got %q", err)
	}

	if err := w.wrap(nil); err != nil {
		t.Errorf("expected no error to stay no error, got %s", err)
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

// Counts from an earlier backend are provisional until every backend has
// succeeded. Otherwise a failed rebuild can make a later legitimate empty
// result look like a collapse from a mapping that was never served.
func TestFailedLaterBackendDoesNotAdvanceEarlierBackendCounts(t *testing.T) {
	first := &fakeConn{entries: map[string][]*goldap.Entry{}}
	second := connWithUsers([]string{"contractors"}, map[string][]string{"bob@example.net": {"contractors"}})

	d := newTestDirectory(t, testConfig(testBackend("first"), testBackend("second")), first, second)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error building the initial mapping: %s", err)
	}

	// The first backend grows, but the complete rebuild is rejected because the
	// second backend fails afterwards.
	first.entries = connWithUsers([]string{"admins"},
		map[string][]string{"alice@example.net": {"admins"}}).entries
	second.searchErr = errors.New("directory is down")
	if err := d.Refresh(); err == nil {
		t.Fatal("expected the rebuild with a failed second backend to fail")
	}

	// Returning to the accepted empty state is legitimate and must not be
	// compared with the unserved intermediate result.
	first.entries = map[string][]*goldap.Entry{}
	second.searchErr = nil
	if err := d.Refresh(); err != nil {
		t.Fatalf("expected the accepted backend counts to remain authoritative, got %s", err)
	}
}

// A mapping is not accepted until it has been persisted. Its counts must not
// become the safety baseline when the store rejects it.
func TestFailedPersistenceDoesNotAdvanceBackendCounts(t *testing.T) {
	c := &fakeConn{entries: map[string][]*goldap.Entry{}}
	store := new(memoryStore)

	d, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error building the initial mapping: %s", err)
	}

	c.entries = connWithUsers([]string{"admins"},
		map[string][]string{"alice@example.net": {"admins"}}).entries
	store.saveErr = errors.New("store is down")
	if err := d.Refresh(); err == nil {
		t.Fatal("expected a mapping that could not be persisted to fail")
	}

	c.entries = map[string][]*goldap.Entry{}
	store.saveErr = nil
	if err := d.Refresh(); err != nil {
		t.Fatalf("expected counts from the unpersisted mapping to be discarded, got %s", err)
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

// A comma escaped inside an RDN value is data, not an RDN separator. Splitting
// DNs on commas used to collapse these two distinct groups onto one key after
// trimming the space, allowing the group returned last to decide the user's
// authorization. The memberOf also uses the equivalent hexadecimal spelling
// of the escaped comma to exercise canonical matching.
func TestRefreshDoesNotConflateEscapedCommasInDNs(t *testing.T) {
	c := &fakeConn{entries: map[string][]*goldap.Entry{
		"OU=Groups,DC=example,DC=net": {
			entry(`CN=Ops\, Admins,OU=Groups,DC=example,DC=net`, map[string][]string{
				"cn": {"cluster-admins"},
			}),
			entry(`CN=Ops\,Admins,OU=Groups,DC=example,DC=net`, map[string][]string{
				"cn": {"viewers"},
			}),
		},
		"OU=Users,DC=example,DC=net": {
			entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
				"userPrincipalName": {"alice@example.net"},
				"memberOf":          {`cn=ops\2C admins, ou=groups, dc=example, dc=net`},
			}),
		},
	}}

	d := newTestDirectory(t, testConfig(), c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, ok := d.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"cluster-admins"}) {
		t.Errorf("expected only the group named by memberOf, got %v (found=%t)", groups, ok)
	}
}

func TestRefreshRejectsMalformedDNs(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	c.entries["OU=Groups,DC=example,DC=net"][0].DN = `CN=broken\`

	d := newTestDirectory(t, testConfig(), c)

	err := d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing a malformed group DN")
	}
	if !strings.Contains(err.Error(), "invalid DN") {
		t.Errorf("expected the error to identify the invalid DN, got %q", err)
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

// Kubernetes treats system: as reserved. A directory group of that name must
// not become an impersonation group, or creating it in a searched OU would
// grant cluster privileges.
func TestRefreshSkipsKubernetesSystemGroups(t *testing.T) {
	c := connWithUsers([]string{"admins", "system:masters", "system:authenticated"},
		map[string][]string{"alice@example.net": {"admins", "system:masters", "system:authenticated"}})

	d := newTestDirectory(t, testConfig(), c)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, ok := d.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected only admins, got %v (found=%t)", groups, ok)
	}

	if stats := d.Stats(); stats.Groups != 1 || stats.Backends[0].Groups != 1 {
		t.Errorf("expected stats to count only the impersonated group, got %+v", stats)
	}
}

// A prefix that keeps the emitted name out of the reserved namespace is the
// intended way to pull a directory group that happens to be called system:.
func TestRefreshKeepsPrefixedSystemGroupNames(t *testing.T) {
	c := connWithUsers([]string{"system:masters"},
		map[string][]string{"alice@example.net": {"system:masters"}})

	backend := testBackend("ldap")
	backend.GroupPrefix = "ldap:"

	d := newTestDirectory(t, testConfig(backend), c)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, ok := d.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"ldap:system:masters"}) {
		t.Errorf("expected the prefixed group to be kept, got %v (found=%t)", groups, ok)
	}
}

// A rebuild that still finds group objects, but none that survive filtering,
// is an emptied mapping and must not replace one that had groups.
func TestRefreshFailsWhenFilteringRemovesEveryGroup(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	d := newTestDirectory(t, testConfig(), c)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	c.entries["OU=Groups,DC=example,DC=net"] = []*goldap.Entry{
		entry("CN=system:masters,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"system:masters"}}),
	}
	c.entries["OU=Users,DC=example,DC=net"] = []*goldap.Entry{
		entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"alice@example.net"},
			"memberOf":          {"CN=system:masters,OU=Groups,DC=example,DC=net"},
		}),
	}

	err := d.Refresh()
	if err == nil {
		t.Fatal("expected an error refreshing after every group was filtered out")
	}
	if !strings.Contains(err.Error(), "returned no groups") {
		t.Errorf("expected the error to say what was empty, got %q", err)
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the previous mapping to be kept, got %v (found=%t)", groups, ok)
	}
}

// Kubernetes group names are case sensitive; only the reserved lowercase
// prefix is privileged.
func TestRefreshKeepsSystemGroupNamesOfADifferentCase(t *testing.T) {
	c := connWithUsers([]string{"System:masters"},
		map[string][]string{"alice@example.net": {"System:masters"}})

	d := newTestDirectory(t, testConfig(), c)
	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, ok := d.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"System:masters"}) {
		t.Errorf("expected the non-reserved name to be kept, got %v (found=%t)", groups, ok)
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

// The full authenticated name must never be tried as an LDAP username before
// its configured prefix is stripped. Otherwise the token user "alice" can be
// assigned the groups of a distinct LDAP user literally named "oidc:alice".
func TestGroupsDoesNotLetPrefixCaptureAnotherLDAPIdentity(t *testing.T) {
	c := connWithUsers([]string{"admins", "viewers"}, map[string][]string{
		"alice@example.net":      {"viewers"},
		"oidc:alice@example.net": {"admins"},
	})

	config := testConfig()
	config.UsernamePrefix = "oidc:"

	d := newTestDirectory(t, config, c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	groups, ok := d.Groups("oidc:alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"viewers"}) {
		t.Errorf("expected the groups of bare LDAP user alice, got %v (found=%t)", groups, ok)
	}
}

func TestGroupsDoesNotFallBackToPrefixedLDAPIdentity(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{
		"oidc:alice@example.net": {"admins"},
	})

	config := testConfig()
	config.UsernamePrefix = "oidc:"

	d := newTestDirectory(t, config, c)

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if groups, ok := d.Groups("oidc:alice@example.net"); ok || groups != nil {
		t.Errorf("expected bare LDAP user alice not to be found, got %v (found=%t)", groups, ok)
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

	w := newWatchdog(time.Minute)
	defer w.stop()

	got, err := d.backends[0].connect(w)
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

func TestConnectSetsTheStartTLSServerName(t *testing.T) {
	config := testConfig()
	config.Backends[0].URLs = []string{"ldap://ldap.example.net:389"}
	config.Backends[0].StartTLS = true

	c := &fakeConn{}
	d := newTestDirectory(t, config, c)

	w := newWatchdog(time.Minute)
	defer w.stop()

	if _, err := d.backends[0].connect(w); err != nil {
		t.Fatalf("unexpected error connecting: %s", err)
	}

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

// memoryStore is a cache.Store that keeps the payload in memory. It reports
// the fingerprint it was last given, as a shared store does, so that what the
// store holds is what decides whether a mapping is written again.
// It is guarded, since a store is shared: a builder writing it and a reader
// reading it are two proxies on two goroutines, as they would be in two pods.
type memoryStore struct {
	mu sync.Mutex

	data        []byte
	fingerprint string

	loadErr        error
	saveErr        error
	fingerprintErr error

	// onSave runs inside Save, so that a test can see what was being served at
	// the moment the mapping was written.
	onSave func()

	saves  int
	loads  int
	probes int
}

var (
	_ cache.Store         = &memoryStore{}
	_ cache.Fingerprinter = &memoryStore{}
)

func (m *memoryStore) Load(_ context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.loads++

	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if m.data == nil {
		return nil, cache.ErrNotFound
	}
	return m.data, nil
}

func (m *memoryStore) Save(_ context.Context, data []byte, fingerprint string) error {
	m.mu.Lock()

	m.saves++
	onSave, saveErr := m.onSave, m.saveErr

	m.mu.Unlock()

	// Outside the lock, since it runs arbitrary test code that may go back
	// into the store.
	if onSave != nil {
		onSave()
	}

	if saveErr != nil {
		return saveErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.data, m.fingerprint = data, fingerprint

	return nil
}

func (m *memoryStore) Fingerprint(_ context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.probes++

	if m.fingerprintErr != nil {
		return "", m.fingerprintErr
	}
	if m.data == nil {
		return "", cache.ErrNotFound
	}
	return m.fingerprint, nil
}

func (m *memoryStore) String() string { return "memory" }

// gatedLoadStore captures one payload and then holds its Load in flight. A
// later Save can therefore publish a newer payload while a reader is still
// installing the captured one.
type gatedLoadStore struct {
	*memoryStore

	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedLoadStore) Load(ctx context.Context) ([]byte, error) {
	data, err := g.memoryStore.Load(ctx)
	if err != nil || g.entered == nil {
		return data, err
	}

	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})

	return data, nil
}

// watchingStore is a memoryStore that reports its changes rather than waiting
// to be asked, as the Secret store does.
type watchingStore struct {
	*memoryStore

	mu       sync.Mutex
	watchers []func(string)
}

var (
	_ cache.Store   = &watchingStore{}
	_ cache.Watcher = &watchingStore{}
)

func newWatchingStore() *watchingStore {
	return &watchingStore{memoryStore: new(memoryStore)}
}

func (w *watchingStore) Watch(_ <-chan struct{}, onChange func(string)) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.watchers = append(w.watchers, onChange)

	return nil
}

func (w *watchingStore) Save(ctx context.Context, data []byte, fingerprint string) error {
	if err := w.memoryStore.Save(ctx, data, fingerprint); err != nil {
		return err
	}

	w.mu.Lock()
	watchers := append([]func(string){}, w.watchers...)
	w.mu.Unlock()

	for _, onChange := range watchers {
		onChange(fingerprint)
	}

	return nil
}

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

	mapping, err := snapshot.mapping()
	if err != nil {
		t.Fatalf("unexpected error resolving the persisted mapping: %s", err)
	}
	if !reflect.DeepEqual(mapping, map[string][]string{"alice@example.net": {"admins"}}) {
		t.Errorf("expected the mapping to have been persisted, got %v", mapping)
	}
	if snapshot.BuiltAt.IsZero() {
		t.Error("expected the persisted mapping to record when it was built")
	}

	if !reflect.DeepEqual(snapshot.Backends, []SnapshotBackend{{Name: "ldap", Users: 1, Groups: 1}}) {
		t.Errorf("expected what each backend contributed to be persisted, got %v", snapshot.Backends)
	}
}

// Group memberships change far less often than they are looked at, and there is
// no partial write - the whole mapping goes out every time it goes out at all -
// so a refresh that rebuilt the mapping the store already holds leaves it be.
func TestRefreshDoesNotRewriteAnUnchangedMapping(t *testing.T) {
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
		t.Fatalf("expected the first mapping to have been persisted, got %d saves", store.saves)
	}

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}
	if store.saves != 1 {
		t.Errorf("expected a rebuild of the same mapping not to rewrite it, got %d saves", store.saves)
	}

	// A group alice has picked up since is a change, and has to reach the
	// store: the whole point of skipping the write is that it was a no-op.
	c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"],
		entry("CN=devs,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"devs"}}))
	c.entries["OU=Users,DC=example,DC=net"] = []*goldap.Entry{
		entry("CN=alice@example.net,OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"alice@example.net"},
			"memberOf": {
				"CN=admins,OU=Groups,DC=example,DC=net",
				"CN=devs,OU=Groups,DC=example,DC=net",
			},
		}),
	}

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}
	if store.saves != 2 {
		t.Fatalf("expected a changed mapping to have been persisted, got %d saves", store.saves)
	}

	snapshot := new(Snapshot)
	if err := json.Unmarshal(store.data, snapshot); err != nil {
		t.Fatalf("unexpected error decoding the persisted mapping: %s", err)
	}

	mapping, err := snapshot.mapping()
	if err != nil {
		t.Fatalf("unexpected error resolving the persisted mapping: %s", err)
	}
	if !reflect.DeepEqual(mapping, map[string][]string{"alice@example.net": {"admins", "devs"}}) {
		t.Errorf("expected the changed mapping to have been persisted, got %v", mapping)
	}
}

// A group nobody is a member of is not part of the mapping, so creating one
// leaves every user holding exactly what they held before. The store is not
// rewritten for it.
//
// It reaches the refresh at all because the group search counts every group
// under the search bases, members or not - that count is what says the search
// returned something. Letting it decide whether the mapping changed would
// rewrite the whole payload for a directory edit that changes nobody's access,
// and on a builder would wake every reader to fetch what it already has.
func TestRefreshDoesNotRewriteForAGroupNobodyBelongsTo(t *testing.T) {
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
		t.Fatalf("expected the first mapping to have been persisted, got %d saves", store.saves)
	}

	before := d.Stats().Groups

	// The group exists in the directory; nobody's memberOf names it.
	c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"],
		entry("CN=nobody-here,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"nobody-here"}}))

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if got := d.Stats().Groups; got != before+1 {
		t.Errorf("expected the group search to have counted the new group, got %d then %d", before, got)
	}

	groups, ok := d.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Fatalf("expected alice to hold the groups she held before, got %v (found=%t)", groups, ok)
	}

	if store.saves != 1 {
		t.Errorf("expected a group nobody belongs to not to rewrite the mapping, got %d saves", store.saves)
	}
}

// readerConfig is the whole of what a reader is configured with: somewhere to
// read the mapping from, and nothing else. No directories, no bind
// credentials, no description of the tree - which is the point of the role.
func readerConfig() *Config {
	return &Config{
		Role: RoleReader,
		Cache: &CacheConfig{
			Type:             CacheTypeKubernetesSecret,
			KubernetesSecret: &SecretCacheConfig{Name: "mapping"},
		},
	}
}

// builderConfig is the deployment on the other side of that store: the one
// that holds the credentials, reaches the directories, and publishes what it
// builds for the readers to serve.
func builderConfig() *Config {
	config := testConfig()

	config.Role = RoleBuilder
	config.Cache = &CacheConfig{
		Type:             CacheTypeKubernetesSecret,
		KubernetesSecret: &SecretCacheConfig{Name: "mapping"},
	}

	return config
}

// A reader serves what a builder published without ever opening a directory.
func TestReaderServesTheMappingTheBuilderPublished(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := newWatchingStore()

	b, err := New(builderConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	b.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}

	// A reader has nothing to dial with, so anything that reached a directory
	// would panic rather than quietly work.
	if len(reader.backends) != 0 {
		t.Fatalf("expected a reader to hold no backends, got %d", len(reader.backends))
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := reader.Run(stopCh); err != nil {
		t.Fatalf("unexpected error starting the reader: %s", err)
	}

	groups, ok := reader.Groups("alice@example.net")
	if !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the published mapping to be served, got %v (found=%t)", groups, ok)
	}

	if stats := reader.Stats(); stats.Source != SourceCache {
		t.Errorf("expected the mapping to be sourced from %q, got %q", SourceCache, stats.Source)
	}

	// Nothing a reader does may reach the store as a write. It is the one
	// guarantee the role exists to make.
	if store.saves != 1 {
		t.Errorf("expected the reader not to have written to the store, got %d saves", store.saves)
	}
}

// A reader takes no traffic until it has a mapping: with an empty one it would
// answer every request by stripping the user of every group they hold. It
// waits rather than exiting, because what it is waiting for is a builder part
// way through its first sweep, and it picks the mapping up as it is published
// rather than at the next poll.
func TestReaderIsNotReadyUntilAMappingIsPublished(t *testing.T) {
	store := newWatchingStore()

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := reader.Run(stopCh); err != nil {
		t.Fatalf("expected a reader with nothing published to start anyway, got %s", err)
	}

	if reader.HasMapping() {
		t.Error("expected a reader with nothing published to have no mapping to serve")
	}

	// The builder finishes its first sweep and publishes.
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	b, err := New(builderConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	b.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	// Which the reader is told about, rather than finding out when it next
	// happens to look.
	if !reader.HasMapping() {
		t.Fatal("expected the reader to pick up the published mapping")
	}

	if groups, ok := reader.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the published mapping to be served, got %v (found=%t)", groups, ok)
	}
}

// A reader does not rebuild, so it never passes through the path that reports
// a rebuild. Left at that it would sit at 0 for its whole life and an alert on
// it would fire on every reader in the deployment, for good.
func TestReaderReportsWhetherItIsKeepingUp(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := newWatchingStore()

	b, err := New(builderConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	b.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	// A reader that starts with a mapping already published, and then watches
	// it never change, is keeping up perfectly well.
	if err := reader.Run(stopCh); err != nil {
		t.Fatalf("unexpected error starting the reader: %s", err)
	}

	if got := testutil.ToFloat64(lastRefreshSuccess); got != 1 {
		t.Errorf("expected a reader serving the published mapping to report 1, got %v", got)
	}

	// And one that can no longer reach the store has stopped keeping up, even
	// though it carries on serving what it already has.
	store.memoryStore.mu.Lock()
	store.fingerprintErr = errors.New("store is down")
	store.memoryStore.mu.Unlock()

	if err := reader.Refresh(); err == nil {
		t.Fatal("expected a refresh against an unreadable store to fail")
	}

	if got := testutil.ToFloat64(lastRefreshSuccess); got != 0 {
		t.Errorf("expected a reader that cannot reach the store to report 0, got %v", got)
	}
}

// A store it cannot read at all is a misconfiguration - the wrong name, or no
// permission to read it - and it would leave the proxy unready for good rather
// than converging. That fails where somebody is watching.
func TestReaderFailsToStartWhenTheStoreCannotBeRead(t *testing.T) {
	store := &memoryStore{loadErr: errors.New("secrets \"mapping\" is forbidden")}

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	err = reader.Run(stopCh)
	if err == nil {
		t.Fatal("expected a reader that cannot read the store to fail to start")
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("expected the error to carry the reason, got %q", err)
	}
}

// A reader is told when a new mapping is published rather than going looking,
// so a store with nothing to tell it would leave it serving the mapping it
// started with until something restarted it. Configuration does not allow one,
// and this is the guard behind that.
func TestReaderRefusesAStoreThatCannotReportChanges(t *testing.T) {
	store := new(memoryStore)

	if _, ok := cache.Store(store).(cache.Watcher); ok {
		t.Fatal("expected the plain store not to be watchable, which is the case under test")
	}

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	err = reader.Run(stopCh)
	if err == nil {
		t.Fatal("expected a reader to refuse a store that cannot report its changes")
	}
	if !strings.Contains(err.Error(), "cannot report when the mapping it holds changes") {
		t.Errorf("expected the error to say why, got %q", err)
	}
}

// Picking up a change must not mean fetching the mapping to find out whether
// there was one: the fingerprint is what says so, and it is read on its own.
func TestReaderFetchesTheMappingOnlyWhenItChanges(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := new(memoryStore)

	b, err := New(builderConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	b.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}

	if err := reader.load(); err != nil {
		t.Fatalf("unexpected error loading: %s", err)
	}

	loads := store.loads

	for range 5 {
		if err := reader.reload(); err != nil {
			t.Fatalf("unexpected error reloading: %s", err)
		}
	}

	if store.loads != loads {
		t.Errorf("expected an unchanged mapping not to be fetched again, got %d fetches",
			store.loads-loads)
	}
	if store.probes < 5 {
		t.Errorf("expected each poll to have asked for the fingerprint, got %d", store.probes)
	}

	// A rebuild that changed something has to reach the reader.
	c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"],
		entry("CN=devs,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"devs"}}))
	c.entries["OU=Users,DC=example,DC=net"] = []*goldap.Entry{
		entry("CN=alice@example.net,OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"alice@example.net"},
			"memberOf": {
				"CN=admins,OU=Groups,DC=example,DC=net",
				"CN=devs,OU=Groups,DC=example,DC=net",
			},
		}),
	}

	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if err := reader.reload(); err != nil {
		t.Fatalf("unexpected error reloading: %s", err)
	}

	if store.loads != loads+1 {
		t.Errorf("expected the changed mapping to have been fetched, got %d fetches", store.loads-loads)
	}

	if groups, ok := reader.Groups("alice@example.net"); !ok ||
		!reflect.DeepEqual(groups, []string{"admins", "devs"}) {
		t.Errorf("expected the changed mapping to be served, got %v (found=%t)", groups, ok)
	}
}

// A reader cannot rebuild anything, so the most it can do when asked is go and
// see whether the builder has published something newer. Refreshing what every
// proxy serves means asking the builder, which is why the refresh endpoint is
// routed to it.
func TestReaderRefreshLooksForANewMapping(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := new(memoryStore)

	b, err := New(builderConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	b.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}

	if err := reader.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing the reader: %s", err)
	}

	if groups, ok := reader.Groups("alice@example.net"); !ok ||
		!reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the published mapping to have been picked up, got %v (found=%t)", groups, ok)
	}

	if store.saves != 1 {
		t.Errorf("expected a reader refresh not to write to the store, got %d saves", store.saves)
	}
}

// A watch notification that arrives while an older load is in flight must
// queue one more reload. Merely joining the old load would acknowledge the
// notification while leaving the reader on the mapping captured before it.
func TestReaderDoesNotLoseAPublicationDuringAnInflightLoad(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})
	store := &gatedLoadStore{memoryStore: new(memoryStore)}

	b, err := New(builderConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	b.backends[0].dial = func(string) (conn, error) { return c, nil }
	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error publishing the initial mapping: %s", err)
	}

	reader, err := New(readerConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building reader: %s", err)
	}
	if err := reader.load(); err != nil {
		t.Fatalf("unexpected error loading the initial mapping: %s", err)
	}

	// Publish B without a watcher involved, then hold a reader load after it
	// has captured B but before it installs it.
	c.entries = connWithUsers([]string{"admins", "devs"},
		map[string][]string{"alice@example.net": {"admins", "devs"}}).entries
	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error publishing mapping B: %s", err)
	}

	store.entered = make(chan struct{})
	store.release = make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(store.release)
		}
	}()

	results := make(chan error, 2)
	go func() { results <- reader.Refresh() }()

	select {
	case <-store.entered:
	case <-time.After(time.Second * 5):
		t.Fatal("expected the reader load of mapping B to start")
	}

	// Publish C, then deliver the equivalent of its watch notification while
	// the load of B is still in flight.
	c.entries = connWithUsers([]string{"admins", "devs", "ops"},
		map[string][]string{"alice@example.net": {"admins", "devs", "ops"}}).entries
	if err := b.Refresh(); err != nil {
		t.Fatalf("unexpected error publishing mapping C: %s", err)
	}
	go func() { results <- reader.Refresh() }()

	// Wait until the notification has joined the in-flight call and marked the
	// follow-up reload before letting the old load finish.
	deadline := time.NewTimer(time.Second * 5)
	tick := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer tick.Stop()
	for {
		reader.refreshMu.Lock()
		pending := reader.inflight != nil && reader.inflight.pending
		reader.refreshMu.Unlock()
		if pending {
			break
		}

		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("expected the newer publication to queue a follow-up reload")
		}
	}

	close(store.release)
	released = true

	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("unexpected error refreshing reader: %s", err)
		}
	}

	if groups, ok := reader.Groups("alice@example.net"); !ok ||
		!reflect.DeepEqual(groups, []string{"admins", "devs", "ops"}) {
		t.Errorf("expected the publication made during the old load to be served, got %v (found=%t)",
			groups, ok)
	}
}

// A store is a shared object, so "has this changed?" is a question about the
// store rather than about what this proxy last wrote to it. A proxy that
// trusted its own memory here would leave a mapping it had been overwritten
// with in place for as long as neither side changed, which is to say for good.
func TestRefreshRewritesAMappingSomethingElseOverwrote(t *testing.T) {
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
		t.Fatalf("expected the first mapping to have been persisted, got %d saves", store.saves)
	}

	// Something else - another proxy sharing this store, or a hand written
	// object - replaces what is in it. This proxy still holds the mapping it
	// wrote, and would skip the write if it went by that alone.
	store.data, store.fingerprint = []byte("someone else's mapping"), "a-different-mapping"

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if store.saves != 2 {
		t.Errorf("expected the overwritten mapping to have been put back, got %d saves", store.saves)
	}
	if store.probes == 0 {
		t.Error("expected the store to have been asked which mapping it holds")
	}

	snapshot := new(Snapshot)
	if err := json.Unmarshal(store.data, snapshot); err != nil {
		t.Fatalf("unexpected error decoding the persisted mapping: %s", err)
	}

	mapping, err := snapshot.mapping()
	if err != nil {
		t.Fatalf("unexpected error resolving the persisted mapping: %s", err)
	}
	if !reflect.DeepEqual(mapping, map[string][]string{"alice@example.net": {"admins"}}) {
		t.Errorf("expected the built mapping to be back in the store, got %v", mapping)
	}
}

// The mapping a proxy restores at startup is by definition the one the store
// holds, so a restart that finds the directories unchanged does not rewrite it
// either. Rollouts are when a mapping is most likely to be rebuilt unchanged.
func TestRestoredMappingIsNotRewrittenWhenUnchanged(t *testing.T) {
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

	// The proxy after the restart, which restores that mapping and then builds
	// the same one from the directory it can still reach.
	after, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	after.backends[0].dial = func(string) (conn, error) { return c, nil }

	stopCh := make(chan struct{})
	defer close(stopCh)

	if err := after.Run(stopCh); err != nil {
		t.Fatalf("unexpected error starting: %s", err)
	}

	if store.saves != 1 {
		t.Errorf("expected the restored mapping not to be rewritten, got %d saves", store.saves)
	}

	if groups, ok := after.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the mapping to be served, got %v (found=%t)", groups, ok)
	}
}

// Nothing but a write moves the build time recorded with a mapping forwards, so
// a mapping that is never rewritten ages past maxAge and is thrown away at
// exactly the restart it exists for.
func TestUnchangedMappingIsRewrittenBeforeItAgesOut(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := new(memoryStore)

	config := testConfig()
	config.Cache = &CacheConfig{
		Type:   CacheTypeFile,
		File:   &FileCacheConfig{Path: filepath.Join(t.TempDir(), "mapping.json")},
		MaxAge: *NewDuration(time.Hour),
	}

	d, err := New(config, store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return c, nil }

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}
	if store.saves != 1 {
		t.Fatalf("expected the first mapping to have been persisted, got %d saves", store.saves)
	}

	// Still inside the half of maxAge that a rewrite is held off for.
	d.persisted.Store(&persistedSnapshot{hash: d.held().hash, builtAt: time.Now().Add(-time.Minute * 20)})

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}
	if store.saves != 1 {
		t.Errorf("expected a mapping well inside maxAge not to be rewritten, got %d saves", store.saves)
	}

	d.persisted.Store(&persistedSnapshot{hash: d.held().hash, builtAt: time.Now().Add(-time.Minute * 40)})

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}
	if store.saves != 2 {
		t.Errorf("expected a mapping halfway to maxAge to be rewritten, got %d saves", store.saves)
	}
}

// internedSnapshot is a snapshot of the given mapping as it would be persisted,
// with everything else about it held constant.
func internedSnapshot(mapping map[string][]string) *Snapshot {
	table, users := internMapping(mapping)

	return &Snapshot{
		Version:     snapshotVersion,
		MappingHash: "configuration",
		BuiltAt:     time.Now(),
		GroupTable:  table,
		Users:       users,
	}
}

// The fingerprint that decides whether the store already holds a mapping.
// Missing a change is the failure that matters: the store would be left holding
// a mapping the directories no longer agree with, and a restart would serve it.
func TestSnapshotContentHash(t *testing.T) {
	base := func() *Snapshot {
		return &Snapshot{
			Version:     snapshotVersion,
			MappingHash: "configuration",
			BuiltAt:     time.Now(),
			Groups:      2,
			Backends:    []SnapshotBackend{{Name: "ldap", Users: 2, Groups: 2}},
			GroupTable:  []string{"admins", "devs"},
			Users:       map[string][]int{"alice@example.net": {0}, "bob@example.net": {0, 1}},
		}
	}

	tests := map[string]struct {
		mutate   func(s *Snapshot)
		expEqual bool
	}{
		"the same mapping built again": {
			mutate:   func(s *Snapshot) {},
			expEqual: true,
		},
		"the same mapping built at a different time": {
			mutate:   func(s *Snapshot) { s.BuiltAt = s.BuiltAt.Add(time.Hour) },
			expEqual: true,
		},
		"a user who has lost a group": {
			mutate: func(s *Snapshot) { s.Users["bob@example.net"] = []int{0} },
		},
		"a user who has gained a group": {
			mutate: func(s *Snapshot) { s.Users["alice@example.net"] = []int{0, 1} },
		},
		"a user who has gone": {
			mutate: func(s *Snapshot) { delete(s.Users, "bob@example.net") },
		},
		"a user who is new": {
			mutate: func(s *Snapshot) { s.Users["carol@example.net"] = []int{1} },
		},
		"a group that has been renamed": {
			mutate: func(s *Snapshot) { s.GroupTable = []string{"admins", "developers"} },
		},
		// The counts describe the searches rather than the mapping. A directory
		// that gained or lost a group nobody belongs to hands back the mapping
		// already in the store, and rewriting it would cost the whole payload -
		// and, on a builder, wake every reader to fetch what it already has.
		"a group nobody belongs to, added to the directory": {
			mutate: func(s *Snapshot) {
				s.Groups = 3
				s.Backends[0].Groups = 3
			},
			expEqual: true,
		},
		// A backend whose users really did fall away loses its entries from the
		// mapping, which is hashed, so the write still happens. The count on its
		// own moving says only that the snapshot was written by a proxy that
		// counted differently.
		"a backend that returned fewer users": {
			mutate:   func(s *Snapshot) { s.Backends[0].Users = 1 },
			expEqual: true,
		},
		"a user who has gone, as that backend's count falls with them": {
			mutate: func(s *Snapshot) {
				delete(s.Users, "bob@example.net")
				s.Backends[0].Users = 1
			},
		},
		// Left unhashed, a snapshot written before the counts were recorded
		// would fingerprint as one that carries them, and the guard they prime
		// would stay unprimed however many times the mapping was rebuilt.
		"a snapshot carrying no per backend counts at all": {
			mutate: func(s *Snapshot) { s.Backends = nil },
		},
		"a mapping built by a differently named backend": {
			mutate: func(s *Snapshot) { s.Backends[0].Name = "other" },
		},
		"a mapping built from a different configuration": {
			mutate: func(s *Snapshot) { s.MappingHash = "other" },
		},
		"a mapping written in a different format": {
			mutate: func(s *Snapshot) { s.Version = snapshotVersion + 1 },
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mutated := base()
			test.mutate(mutated)

			if equal := base().contentHash() == mutated.contentHash(); equal != test.expEqual {
				t.Errorf("expected fingerprints to be equal=%t for %s, got equal=%t",
					test.expEqual, name, equal)
			}
		})
	}

	// The same mapping is the same mapping however it was assembled: the same
	// users holding the same groups fingerprints the same way, whatever order
	// the groups of a user came back from a directory in.
	shuffled := internedSnapshot(map[string][]string{
		"alice@example.net": {"admins"},
		"bob@example.net":   {"devs", "admins"},
	})
	ordered := internedSnapshot(map[string][]string{
		"bob@example.net":   {"admins", "devs"},
		"alice@example.net": {"admins"},
	})

	if shuffled.contentHash() != ordered.contentHash() {
		t.Error("expected the same users holding the same groups to fingerprint the same way")
	}

	// And a user who actually holds a different group does not.
	different := internedSnapshot(map[string][]string{
		"alice@example.net": {"admins"},
		"bob@example.net":   {"admins", "ops"},
	})

	if ordered.contentHash() == different.contentHash() {
		t.Error("expected a user holding a different group to fingerprint differently")
	}

	// Group names are not a fixed width, so a table that runs two of them
	// together must not fingerprint as one that divides them elsewhere.
	run, divided := base(), base()
	run.GroupTable = []string{"ab", "c"}
	divided.GroupTable = []string{"a", "bc"}

	if run.contentHash() == divided.contentHash() {
		t.Error("expected group names that concatenate the same way to fingerprint differently")
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

// Serving a mapping that could not be persisted is what lets a restart go
// backwards, so it fails the refresh and the previous mapping - the one the
// store still holds - keeps serving.
func TestRefreshFailsWhenPersistingFails(t *testing.T) {
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

	// The store breaks, and the directory grows a group, after the first
	// mapping was built and persisted.
	store.saveErr = errors.New("store is down")
	c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"],
		entry("CN=devs,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"devs"}}))
	c.entries["OU=Users,DC=example,DC=net"] = []*goldap.Entry{
		entry("CN=alice@example.net,OU=Users,DC=example,DC=net", map[string][]string{
			"userPrincipalName": {"alice@example.net"},
			"memberOf": {
				"CN=admins,OU=Groups,DC=example,DC=net",
				"CN=devs,OU=Groups,DC=example,DC=net",
			},
		}),
	}

	err = d.Refresh()
	if err == nil {
		t.Fatal("expected a refresh that could not be persisted to fail")
	}
	if !strings.Contains(err.Error(), "failed to persist") {
		t.Errorf("expected the error to say persisting failed, got %q", err)
	}

	// What is served has to still match what the store holds, or a restart
	// would go backwards from it.
	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the persisted mapping to still be the one served, got %v (found=%t)", groups, ok)
	}

	if got := testutil.ToFloat64(lastRefreshSuccess); got != 0 {
		t.Errorf("expected a refresh that could not be persisted to report 0, got %v", got)
	}
}

// The ordering the whole thing rests on: nothing is served until the store has
// it.
func TestMappingIsPersistedBeforeItIsServed(t *testing.T) {
	c := connWithUsers([]string{"admins"}, map[string][]string{"alice@example.net": {"admins"}})

	store := new(memoryStore)

	d, err := New(testConfig(), store)
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}
	d.backends[0].dial = func(string) (conn, error) { return c, nil }

	var servedDuringSave []string
	var foundDuringSave bool

	store.onSave = func() {
		servedDuringSave, foundDuringSave = d.Groups("alice@example.net")
	}

	if err := d.Refresh(); err != nil {
		t.Fatalf("unexpected error refreshing: %s", err)
	}

	if foundDuringSave {
		t.Errorf("expected the new mapping not to be served until it was persisted, got %v", servedDuringSave)
	}

	if groups, ok := d.Groups("alice@example.net"); !ok || !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected the mapping to be served once persisted, got %v (found=%t)", groups, ok)
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
		GroupTable:  []string{"admins"},
		Users:       map[string][]int{"alice@example.net": {0}},
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
		"a snapshot naming a group its table does not hold": {
			mutate: func(s *Snapshot) { s.Users = map[string][]int{"alice@example.net": {1}} },
			expErr: "outside the table",
		},
		"a snapshot with no group table": {
			mutate: func(s *Snapshot) { s.GroupTable = nil },
			expErr: "outside the table",
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

			if _, _, err := d.decodeSnapshot(data); err == nil {
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

	if _, _, err := d.decodeSnapshot(data); err != nil {
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
		"a changed timeout":       {func(c *Config) { c.Backends[0].Timeout = NewDuration(time.Hour) }, false},
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
