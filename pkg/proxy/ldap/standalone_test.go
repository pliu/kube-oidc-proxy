// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
)

func TestStandaloneLookupSecurityRules(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*fakeConn)
		want    []string
		failure string
	}{
		"duplicate user": {func(c *fakeConn) {
			c.entries["OU=Users,DC=example,DC=net"] = append(c.entries["OU=Users,DC=example,DC=net"], entry("CN=other,OU=Users,DC=example,DC=net", map[string][]string{"userPrincipalName": {"alice"}}))
		}, nil, "ambiguous"},
		"duplicate group name": {func(c *fakeConn) {
			c.entries["OU=Groups,DC=example,DC=net"] = append(c.entries["OU=Groups,DC=example,DC=net"], entry("CN=other,OU=Groups,DC=example,DC=net", map[string][]string{"cn": {"Admins"}}))
		}, nil, "ambiguous"},
		"malformed DN": {func(c *fakeConn) {
			for _, a := range c.entries["OU=Users,DC=example,DC=net"][0].Attributes {
				if strings.EqualFold(a.Name, "memberOf") {
					a.Values = []string{"invalid"}
				}
			}
		}, nil, "invalid"},
		"reserved groups": {func(c *fakeConn) {
			dn := "CN=Admins,OU=Groups,DC=example,DC=net"
			c.entries[dn][0].Attributes[0].Values = []string{"system:masters"}
		}, []string{}, ""},
		"outside group base": {func(c *fakeConn) {
			c.entries["OU=Users,DC=example,DC=net"][0] = entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{"userPrincipalName": {"alice"}, "memberOf": {"CN=Admins,OU=Other,DC=example,DC=net"}})
		}, []string{}, ""},
		"deleted group": {func(c *fakeConn) { delete(c.entries, "CN=Admins,OU=Groups,DC=example,DC=net") }, []string{}, ""},
		"duplicate memberships": {func(c *fakeConn) {
			c.entries["OU=Users,DC=example,DC=net"][0] = entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{"userPrincipalName": {"alice"}, "memberOf": {"CN=Admins,OU=Groups,DC=example,DC=net", "cn=admins,ou=groups,dc=example,dc=net"}})
		}, []string{"Admins"}, ""},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := connWithUsers([]string{"Admins"}, map[string][]string{"alice": {"Admins"}})
			test.mutate(c)
			d := newTestResolver(t, testConfig(), c)
			groups, err := d.searchUser(context.Background(), "alice", false)
			if test.failure != "" {
				if err == nil || !strings.Contains(err.Error(), test.failure) {
					t.Fatalf("wanted %s: %v", test.failure, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(groups, test.want) {
				t.Fatalf("%v %v", groups, err)
			}
		})
	}
}

func TestStandaloneLookupMergesAllBackendsAndRejectsPartialResult(t *testing.T) {
	a := connWithUsers([]string{"One", "Shared"}, map[string][]string{"alice": {"One", "Shared"}})
	b := connWithUsers([]string{"Two", "Shared"}, map[string][]string{"alice": {"Two", "Shared"}})
	d := newTestResolver(t, testConfig(testBackend("a"), testBackend("b")), a, b)
	groups, err := d.searchUser(context.Background(), "alice", false)
	if err != nil || !reflect.DeepEqual(groups, []string{"One", "Shared", "Two"}) {
		t.Fatalf("%v %v", groups, err)
	}
	b.searchErr = errors.New("unavailable")
	if groups, err := d.searchUser(context.Background(), "alice", false); err == nil || groups != nil {
		t.Fatal("partial backend contribution accepted")
	}
}

func TestStandaloneLookupRangedMemberships(t *testing.T) {
	c := connWithRangedUser("alice", []string{"One", "Two", "Three"}, 1)
	// The range fixture supplies group enumeration; expose base-object lookups.
	for _, e := range c.entries["OU=Groups,DC=example,DC=net"] {
		c.entries[e.DN] = []*goldap.Entry{e}
	}
	original := c.searchFn
	c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
		if req.BaseDN == "CN=alice,OU=Users,DC=example,DC=net" {
			return original(req)
		}
		return &goldap.SearchResult{Entries: c.entries[req.BaseDN]}, nil
	}
	d := newTestResolver(t, testConfig(), c)
	groups, err := d.searchUser(context.Background(), "alice", false)
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
		if _, err := d.searchUser(context.Background(), "alice*)(uid=*)", false); err != nil {
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
			dns[i] = fmt.Sprintf("CN=group-%d,OU=Groups,DC=example,DC=net", i)
		}
		user := entry("CN=alice,OU=Users,DC=example,DC=net", map[string][]string{"userPrincipalName": {"alice"}, "memberOf": dns})
		c.searchFn = func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
			if req.BaseDN == "OU=Users,DC=example,DC=net" {
				return &goldap.SearchResult{Entries: []*goldap.Entry{user}}, nil
			}
			if req.Scope == goldap.ScopeBaseObject {
				return &goldap.SearchResult{Entries: []*goldap.Entry{entry(req.BaseDN, map[string][]string{"cn": {req.BaseDN}})}}, nil
			}
			return &goldap.SearchResult{}, nil
		}
		d := newTestResolver(t, testConfig(), c)
		groups, err := d.searchUser(context.Background(), "alice", false)
		if err == nil || !strings.Contains(err.Error(), "exceeds the limit") || groups != nil {
			t.Fatalf("truncated lookup accepted: %v %v", groups, err)
		}
	})
}
