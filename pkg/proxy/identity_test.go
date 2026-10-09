// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"reflect"
	"slices"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
)

func TestBuildImpersonationPreservesIdentity(t *testing.T) {
	requester := &user.DefaultInfo{
		Name: "alice", UID: "alice-id", Groups: []string{"requester-group"},
		Extra: map[string][]string{"scope": {"requester-scope"}},
	}
	target := &user.DefaultInfo{
		Name: "bob", UID: "bob-id", Groups: []string{"target-group"},
		Extra: map[string][]string{"scope": {"target-scope"}},
	}
	config := &Config{
		ExtraUserHeaders:                map[string][]string{"scope": {"configured"}},
		ExtraUserHeadersClientIPEnabled: true,
	}
	for _, impersonate := range []bool{false, true} {
		t.Run(map[bool]string{false: "requester", true: "target"}[impersonate], func(t *testing.T) {
			var selected user.Info
			effective := requester
			if impersonate {
				selected, effective = target, target
			}
			result, err := buildImpersonation(requester, selected, "192.0.2.1", config)
			if err != nil {
				t.Fatal(err)
			}
			forwarded := result.ImpersonationConfig
			if forwarded.UserName != effective.Name || forwarded.UID != effective.UID ||
				result.InboundUser != requester || result.ImpersonatedUser != selected {
				t.Fatalf("incorrect requester or effective identity: %+v", result)
			}
			if !reflect.DeepEqual(forwarded.Groups, []string{effective.Groups[0], user.AllAuthenticated}) ||
				!reflect.DeepEqual(forwarded.Extra["scope"], []string{effective.Extra["scope"][0], "configured"}) ||
				!reflect.DeepEqual(forwarded.Extra[UserHeaderClientIPKey], []string{"192.0.2.1"}) {
				t.Fatalf("incorrect outgoing identity: %+v", forwarded)
			}
			if impersonate {
				for key, want := range map[string][]string{
					"originaluser.jetstack.io-user":   {"alice"},
					"originaluser.jetstack.io-uid":    {"alice-id"},
					"originaluser.jetstack.io-groups": {"requester-group"},
					"originaluser.jetstack.io-extra":  {`{"scope":["requester-scope"]}`},
				} {
					if !reflect.DeepEqual(forwarded.Extra[key], want) {
						t.Fatalf("incorrect original requester %q: %v", key, forwarded.Extra[key])
					}
				}
			} else if _, ok := forwarded.Extra["originaluser.jetstack.io-user"]; ok {
				t.Fatal("ordinary request includes impersonation provenance")
			}
			// Verify the outgoing fields have independent storage, even after
			// callers or transport code modify their contents.
			forwarded.Groups[0] = "modified"
			forwarded.Extra["scope"][0] = "modified"
			forwarded.Extra["scope"][1] = "modified"
			if !reflect.DeepEqual(requester.Groups, []string{"requester-group"}) ||
				!reflect.DeepEqual(target.Groups, []string{"target-group"}) ||
				!reflect.DeepEqual(requester.Extra, map[string][]string{"scope": {"requester-scope"}}) ||
				!reflect.DeepEqual(target.Extra, map[string][]string{"scope": {"target-scope"}}) ||
				!reflect.DeepEqual(config.ExtraUserHeaders, map[string][]string{"scope": {"configured"}}) {
				t.Fatal("outgoing identity shares storage with an input")
			}
		})
	}
}

func TestBuildImpersonationBuiltinGroups(t *testing.T) {
	for _, test := range []struct {
		name         string
		groups, want []string
	}{
		{"alice", nil, []string{user.AllAuthenticated}},
		{"alice", []string{user.AllAuthenticated}, []string{user.AllAuthenticated}},
		{"alice", []string{user.AllUnauthenticated}, []string{user.AllUnauthenticated}},
		{user.Anonymous, nil, []string{user.AllUnauthenticated}},
		{user.Anonymous, []string{user.AllUnauthenticated}, []string{user.AllUnauthenticated}},
	} {
		identity := &user.DefaultInfo{Name: test.name, Groups: test.groups}
		result, err := buildImpersonation(identity, nil, "", &Config{})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(result.ImpersonationConfig.Groups, test.want) {
			t.Errorf("%q with groups %v: got %v, want %v", test.name, test.groups, result.ImpersonationConfig.Groups, test.want)
		}
	}
}

func TestWithoutReservedGroups(t *testing.T) {
	unreserved := &user.DefaultInfo{Name: "alice", Groups: []string{"developers", "ops"}}
	if got := withoutReservedGroups(unreserved, "192.0.2.1"); got != unreserved {
		t.Fatalf("identity without reserved groups was replaced: %+v", got)
	}

	claimed := &user.DefaultInfo{
		Name: "alice", UID: "alice-id",
		Groups: []string{"system:masters", "developers", "system:authenticated", "systems", "system:serviceaccounts"},
		Extra:  map[string][]string{"scope": {"openid"}},
	}
	original := slices.Clone(claimed.Groups)

	got := withoutReservedGroups(claimed, "192.0.2.1")
	if !reflect.DeepEqual(got.GetGroups(), []string{"developers", "systems"}) {
		t.Errorf("unexpected groups: %q", got.GetGroups())
	}
	if got.GetName() != "alice" || got.GetUID() != "alice-id" || !reflect.DeepEqual(got.GetExtra(), claimed.Extra) {
		t.Errorf("identity not otherwise preserved: %+v", got)
	}
	if !reflect.DeepEqual(claimed.Groups, original) {
		t.Errorf("token identity was modified: %q", claimed.Groups)
	}
}
