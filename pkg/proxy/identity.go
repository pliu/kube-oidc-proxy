// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/reqctx"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"
)

// buildImpersonation assembles an already-authorized identity for forwarding.
// A nil target means act as the requester. Groups and extras are copied so
// construction and subsequent transport use cannot mutate either identity.
func buildImpersonation(requester, target user.Info, remoteAddr string, config *Config) (*reqctx.ImpersonationRequest, error) {
	effective := requester
	if target != nil {
		effective = target
	}

	groups := slices.Clone(effective.GetGroups())
	if effective.GetName() == user.Anonymous {
		if !slices.Contains(groups, user.AllUnauthenticated) {
			groups = append(groups, user.AllUnauthenticated)
		}
	} else if !slices.Contains(groups, user.AllAuthenticated) && !slices.Contains(groups, user.AllUnauthenticated) {
		groups = append(groups, user.AllAuthenticated)
	}

	extra := make(map[string][]string, len(effective.GetExtra()))
	for key, values := range effective.GetExtra() {
		extra[key] = slices.Clone(values)
	}
	if config.ExtraUserHeadersClientIPEnabled {
		extra[UserHeaderClientIPKey] = append(extra[UserHeaderClientIPKey], remoteAddr)
	}
	for key, values := range config.ExtraUserHeaders {
		extra[key] = append(extra[key], values...)
	}

	if target != nil {
		extra["originaluser.jetstack.io-user"] = []string{requester.GetName()}
		if len(requester.GetGroups()) > 0 {
			extra["originaluser.jetstack.io-groups"] = slices.Clone(requester.GetGroups())
		}
		if requester.GetUID() != "" {
			extra["originaluser.jetstack.io-uid"] = []string{requester.GetUID()}
		}
		if len(requester.GetExtra()) > 0 {
			encoded, err := json.Marshal(requester.GetExtra())
			if err != nil {
				return nil, err
			}
			extra["originaluser.jetstack.io-extra"] = []string{string(encoded)}
		}
	}

	return &reqctx.ImpersonationRequest{
		ImpersonationConfig: &transport.ImpersonationConfig{
			UserName: effective.GetName(),
			UID:      effective.GetUID(),
			Groups:   groups,
			Extra:    extra,
		},
		InboundUser:      requester,
		ImpersonatedUser: target,
	}, nil
}

// reservedGroupPrefix starts the groups Kubernetes reserves for identities it
// assigns itself, such as system:masters.
const reservedGroupPrefix = "system:"

// withoutReservedGroups removes the groups of an authenticated token that use
// the reserved system: prefix.
//
// The proxy may impersonate any group, so a group its token claims is a group
// the request runs with. A token claiming system:masters - from an identity
// provider that lets a user name their own groups, or a claim mapping without
// a prefix - would otherwise run the request as cluster-admin, and would take
// part in the reviews authorizing impersonation too, where system:masters is
// allowed everything. Dropped here, before anything reads the identity, so
// that no later step can see them. Groups authorized through Impersonate-Group
// are not affected. system:authenticated is added back when the request is
// impersonated.
func withoutReservedGroups(u user.Info, remoteAddr string) user.Info {
	groups := u.GetGroups()
	if !slices.ContainsFunc(groups, isReservedGroup) {
		return u
	}

	kept := make([]string, 0, len(groups))
	for _, group := range groups {
		if isReservedGroup(group) {
			klog.V(2).Infof("dropping reserved group %q from the token of %q (%s)",
				group, u.GetName(), remoteAddr)
			continue
		}

		kept = append(kept, group)
	}

	return &user.DefaultInfo{
		Name:   u.GetName(),
		UID:    u.GetUID(),
		Groups: kept,
		Extra:  u.GetExtra(),
	}
}

func isReservedGroup(group string) bool {
	return strings.HasPrefix(group, reservedGroupPrefix)
}
