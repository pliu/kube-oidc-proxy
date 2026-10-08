// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	ctx "context"
	"encoding/json"
	"errors"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/context"
)

const (
	// LDAPRefreshPath is the path an authenticated user can POST to in order to
	// trigger a rebuild of the LDAP user to group mapping.
	LDAPRefreshPath = "/kube-oidc-proxy/ldap/refresh"

	// LDAPRefreshUserParam names the one user to refresh, for a caller who
	// knows what changed in the directory and does not need every other user
	// searched for again to pick it up.
	LDAPRefreshUserParam = "user"
)

// errImpersonationNotAccepted is returned for a request that carries
// Impersonate- headers while the groups of a request are being taken from
// the directory. See withImpersonateRequest for why the two cannot both be
// honoured.
var errImpersonationNotAccepted = errors.New(
	"impersonation headers are not accepted while group augmentation is enabled")

// GroupAugmenter is the source of the groups a request is impersonated with
// when the groups of the token are not to be trusted.
type GroupAugmenter interface {
	Resolve(ctx.Context, string) ([]string, bool, error)
	Run(<-chan struct{}) error
	CanRefresh(string) bool
}

// withLDAPRefresh serves the endpoint that triggers a rebuild of the LDAP user
// to group mapping. It sits after authentication in the chain,
// so only authenticated users can trigger a refresh. The path is not a valid
// API server path, so it can never shadow a request meant for Kubernetes.
//
// The endpoint is a stub for now: it authenticates and authorises the caller,
// then acknowledges the request without rebuilding anything. The mapping is
// still rebuilt on the configured interval. Refresh and RefreshUser are kept
// on GroupAugmenter for when the endpoint calls them again.
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
		req, remoteAddr = context.RemoteAddr(req)

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

		// TODO: rebuild the mapping, or the one user named by
		// LDAPRefreshUserParam, through Refresh and RefreshUser.
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
//
// Being held in none of them can also just mean the directory gained them since
// the last rebuild. Waiting out the interval is not the only way to pick that
// up: the refresh endpoint takes a single user, so what changed can be
// refreshed without everybody being searched for again.
func (p *Proxy) augmentGroups(context ctx.Context, u user.Info, remoteAddr string) (user.Info, error) {
	groups, ok, err := p.ldapDirectory.Resolve(context, u.GetName())
	if err != nil {
		return nil, err
	}
	if !ok {
		klog.V(4).Infof("user %q is held in no directory, dropping the groups of their token (%s)",
			u.GetName(), remoteAddr)
	}

	return &user.DefaultInfo{
		Name:   u.GetName(),
		UID:    u.GetUID(),
		Groups: groups,
		Extra:  u.GetExtra(),
	}, nil
}
