// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

// recordGroups returns groups as a record built from them stores them:
// ordered, and each given once. searchUser leaves that to the record.
func recordGroups(t *testing.T, groups []string) []string {
	t.Helper()
	record, err := cache.NewUserRecord("alice", groups, "fingerprint", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return record.Groups
}

func TestStandaloneLookupSecurityRules(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*fakeConn)
		want    []string
		failure string
	}{
		"duplicate user": {func(c *fakeConn) {
			c.entries[usersBase] = append(c.entries[usersBase], entry(userDN("other"), map[string][]string{"userPrincipalName": {"alice"}}))
		}, nil, "ambiguous"},
		"duplicate group name": {func(c *fakeConn) {
			c.entries[groupsBase] = append(c.entries[groupsBase], entry(groupDN("other"), map[string][]string{"cn": {"Admins"}}))
		}, nil, "ambiguous"},
		"malformed DN": {func(c *fakeConn) {
			for _, a := range c.entries[usersBase][0].Attributes {
				if strings.EqualFold(a.Name, "memberOf") {
					a.Values = []string{"invalid"}
				}
			}
		}, nil, "invalid"},
		"reserved groups": {func(c *fakeConn) {
			dn := groupDN("Admins")
			c.entries[dn][0].Attributes[0].Values = []string{"system:masters"}
		}, []string{}, ""},
		"outside group base": {func(c *fakeConn) {
			c.entries[usersBase][0] = entry(userDN("alice"), map[string][]string{"userPrincipalName": {"alice"}, "memberOf": {"CN=Admins,OU=Other,DC=example,DC=net"}})
		}, []string{}, ""},
		"deleted group": {func(c *fakeConn) { delete(c.entries, groupDN("Admins")) }, []string{}, ""},
		"duplicate memberships": {func(c *fakeConn) {
			c.entries[usersBase][0] = entry(userDN("alice"), map[string][]string{"userPrincipalName": {"alice"}, "memberOf": {groupDN("Admins"), "cn=admins,ou=groups,dc=example,dc=net"}})
		}, []string{"Admins"}, ""},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := connWithUsers([]string{"Admins"}, map[string][]string{"alice": {"Admins"}})
			test.mutate(c)
			d := newTestResolver(t, testConfig(), c)
			groups, err := d.searchUser(context.Background(), "alice")
			if test.failure != "" {
				if err == nil || !strings.Contains(err.Error(), test.failure) {
					t.Fatalf("wanted %s: %v", test.failure, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(recordGroups(t, groups), test.want) {
				t.Fatalf("%v %v", groups, err)
			}
		})
	}
}

func TestStandaloneLookupMergesAllBackendsAndRejectsPartialResult(t *testing.T) {
	a := connWithUsers([]string{"One", "Shared"}, map[string][]string{"alice": {"One", "Shared"}})
	b := connWithUsers([]string{"Two", "Shared"}, map[string][]string{"alice": {"Two", "Shared"}})
	d := newTestResolver(t, testConfig(testBackend("a"), testBackend("b")), a, b)
	groups, err := d.searchUser(context.Background(), "alice")
	if err != nil || !reflect.DeepEqual(recordGroups(t, groups), []string{"One", "Shared", "Two"}) {
		t.Fatalf("%v %v", groups, err)
	}
	b.searchErr = errors.New("unavailable")
	if groups, err := d.searchUser(context.Background(), "alice"); err == nil || groups != nil {
		t.Fatal("partial backend contribution accepted")
	}
}

func TestStandaloneLookupRangedMemberships(t *testing.T) {
	c := connWithRangedUser("alice", []string{"One", "Two", "Three"}, 1)
	// The range fixture supplies group enumeration; expose base-object lookups.
	for _, e := range c.entries[groupsBase] {
		c.entries[e.DN] = []*goldap.Entry{e}
	}
	original := c.searchFn
	c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
		if req.BaseDN == userDN("alice") {
			return original(req)
		}
		return &goldap.SearchResult{Entries: c.entries[req.BaseDN]}, nil
	}
	d := newTestResolver(t, testConfig(), c)
	groups, err := d.searchUser(context.Background(), "alice")
	if err != nil || len(groups) != 3 {
		t.Fatalf("%v %v", groups, err)
	}
}

func TestStandaloneLookupEscapesUsernameAndBoundsGroups(t *testing.T) {
	t.Run("escaped username", func(t *testing.T) {
		c := connWithUsers(nil, nil)
		var filter string
		c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
			filter = req.Filter
			return &goldap.SearchResult{}, nil
		}
		d := newTestResolver(t, testConfig(), c)
		if _, err := d.searchUser(context.Background(), "alice*)(uid=*)"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(filter, goldap.EscapeFilter("alice*)(uid=*)")) {
			t.Fatalf("unescaped username: %s", filter)
		}
	})
	t.Run("group work limit", func(t *testing.T) {
		c := connWithUsers(nil, nil)
		dns := make([]string, maxGroupDiscoveries+1)
		for i := range dns {
			dns[i] = groupDN(fmt.Sprintf("group-%d", i))
		}
		user := entry(userDN("alice"), map[string][]string{"userPrincipalName": {"alice"}, "memberOf": dns})
		c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
			if req.BaseDN == usersBase {
				return &goldap.SearchResult{Entries: []*goldap.Entry{user}}, nil
			}
			if req.Scope == goldap.ScopeBaseObject {
				return &goldap.SearchResult{Entries: []*goldap.Entry{entry(req.BaseDN, map[string][]string{"cn": {req.BaseDN}})}}, nil
			}
			return &goldap.SearchResult{}, nil
		}
		d := newTestResolver(t, testConfig(), c)
		groups, err := d.searchUser(context.Background(), "alice")
		if err == nil || !strings.Contains(err.Error(), "exceeds the limit") || groups != nil {
			t.Fatalf("truncated lookup accepted: %v %v", groups, err)
		}
	})
}
