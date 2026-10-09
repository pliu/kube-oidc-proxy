// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"encoding/json"
	"slices"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/reqctx"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/transport"
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
