// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"slices"
	"strings"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/reqctx"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"
)

// buildImpersonation assembles the identity a request is forwarded as: the
// requester's own. Groups and extras are copied so construction and subsequent
// transport use cannot mutate the identity the request context holds.
func buildImpersonation(requester user.Info, remoteAddr string, config *Config) *reqctx.ImpersonationRequest {
	groups := slices.Clone(requester.GetGroups())
	if requester.GetName() == user.Anonymous {
		if !slices.Contains(groups, user.AllUnauthenticated) {
			groups = append(groups, user.AllUnauthenticated)
		}
	} else if !slices.Contains(groups, user.AllAuthenticated) && !slices.Contains(groups, user.AllUnauthenticated) {
		groups = append(groups, user.AllAuthenticated)
	}

	extra := make(map[string][]string, len(requester.GetExtra()))
	for key, values := range requester.GetExtra() {
		extra[key] = slices.Clone(values)
	}
	if config.ExtraUserHeadersClientIPEnabled {
		extra[UserHeaderClientIPKey] = append(extra[UserHeaderClientIPKey], remoteAddr)
	}
	for key, values := range config.ExtraUserHeaders {
		extra[key] = append(extra[key], values...)
	}

	return &reqctx.ImpersonationRequest{
		ImpersonationConfig: &transport.ImpersonationConfig{
			UserName: requester.GetName(),
			UID:      requester.GetUID(),
			Groups:   groups,
			Extra:    extra,
		},
		InboundUser: requester,
	}
}

// reservedPrefix starts the users and groups Kubernetes reserves for
// identities it assigns itself, such as system:masters,
// system:serviceaccount:<namespace>:<name> and system:anonymous.
const reservedPrefix = "system:"

// isReservedUsername reports whether a token names one of the identities
// Kubernetes reserves. The proxy may impersonate any user, service accounts
// included, so a token whose username is system:serviceaccount:kube-system:x -
// from an identity provider that lets a user influence their username, or a
// claim mapping without a prefix - would run the request as that service
// account, with whatever it is allowed. Such a token is refused rather than
// stripped, as there is no identity left to run it as.
func isReservedUsername(name string) bool {
	return strings.HasPrefix(name, reservedPrefix)
}

// withoutReservedGroups removes the groups of an authenticated token that use
// the reserved system: prefix.
//
// The proxy may impersonate any group, so a group its token claims is a group
// the request runs with. A token claiming system:masters - from an identity
// provider that lets a user name their own groups, or a claim mapping without
// a prefix - would otherwise run the request as cluster-admin. Dropped here,
// before anything reads the identity, so that no later step can see them.
// system:authenticated is added back when the request is impersonated.
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
	return strings.HasPrefix(group, reservedPrefix)
}
