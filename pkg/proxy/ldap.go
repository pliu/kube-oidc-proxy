// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"encoding/json"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/reqctx"
)

const (
	// LDAPRefreshPath is the path an authenticated user can POST to in order to
	// request a refresh (currently a stub).
	LDAPRefreshPath = "/kube-oidc-proxy/ldap/refresh"
)

// GroupAugmenter is the source of the groups a request is impersonated with
// when the groups of the token are not to be trusted.
type GroupAugmenter interface {
	Resolve(context.Context, string) ([]string, error)
	Run(<-chan struct{}) error
	CanRefresh(string) bool
}

// withLDAPRefresh authenticates and authorizes the stub refresh endpoint.
// It acknowledges the request without performing work. Periodic cached-user
// refresh is handled independently by the elected leader.
func (p *Proxy) withLDAPRefresh(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if p.ldapDirectory == nil || req.URL.Path != LDAPRefreshPath {
			handler.ServeHTTP(rw, req)
			return
		}

		if req.Method != http.MethodPost {
			rw.Header().Set("Allow", http.MethodPost)
			http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var remoteAddr string
		req, remoteAddr = reqctx.RemoteAddr(req)

		// A request that authenticated by token passthrough carries no user,
		// so there is nobody to check against the allowed users.
		requester, ok := genericapirequest.UserFrom(req.Context())
		if !ok || len(requester.GetName()) == 0 {
			p.handleError(rw, req, errNoName)
			return
		}

		if !p.ldapDirectory.CanRefresh(requester.GetName()) {
			klog.V(2).Infof("user %q is not allowed to trigger an LDAP refresh (%s)",
				requester.GetName(), remoteAddr)
			http.Error(rw, "Not allowed to trigger an LDAP refresh", http.StatusForbidden)
			return
		}

		klog.V(2).Infof("LDAP refresh requested by %q (%s), which is not implemented yet",
			requester.GetName(), remoteAddr)

		rw.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(rw).Encode(struct{}{}); err != nil {
			klog.Errorf("failed to write LDAP refresh response (%s): %s", remoteAddr, err)
		}
	})
}

// augmentGroups replaces the groups of the given user with the groups they hold
// in the LDAP directories.
//
// A user held in none of them is given no groups at all, and so can do only
// what system:authenticated allows. The groups of their token are not a
// fallback: the directory being the only thing that decides group membership is
// the whole point of augmenting, and a user who is missing because a directory
// is misconfigured would otherwise quietly regain whatever their identity
// provider claimed for them.
func (p *Proxy) augmentGroups(ctx context.Context, u user.Info) (user.Info, error) {
	groups, err := p.ldapDirectory.Resolve(ctx, u.GetName())
	if err != nil {
		return nil, err
	}

	return &user.DefaultInfo{
		Name:   u.GetName(),
		UID:    u.GetUID(),
		Groups: groups,
		Extra:  u.GetExtra(),
	}, nil
}
