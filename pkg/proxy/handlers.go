// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/context"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/logging"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
)

func (p *Proxy) withHandlers(handler http.Handler) http.Handler {
	// Set up proxy handlers
	handler = p.auditor.WithRequest(handler)
	handler = p.withImpersonateRequest(handler)
	handler = p.withLDAPRefresh(handler)
	handler = p.withAuthenticateRequest(handler)

	// Add the auditor backend as a shutdown hook
	p.hooks.AddPreShutdownHook("AuditBackend", p.auditor.Shutdown)

	return handler
}

// withAuthenticateRequest adds the proxy authentication handler to a chain.
func (p *Proxy) withAuthenticateRequest(handler http.Handler) http.Handler {
	tokenReviewHandler := p.withTokenReview(handler)

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Auth request and handle unauthed
		info, ok, err := p.oidcRequestAuther.AuthenticateRequest(req)
		if err != nil {
			klog.V(5).Infof("Authenticated request failed: %s", err)
			// Since we have failed OIDC auth, we will try a token review, if enabled.
			tokenReviewHandler.ServeHTTP(rw, req)
			return
		}

		// Failed authorization
		if !ok {
			p.handleError(rw, req, errUnauthorized)
			return
		}

		var remoteAddr string
		req, remoteAddr = context.RemoteAddr(req)

		klog.V(4).Infof("authenticated request: %s", remoteAddr)

		// Add the user info to the request context
		req = req.WithContext(genericapirequest.WithUser(req.Context(), info.User))
		handler.ServeHTTP(rw, req)
	})
}

// withTokenReview will attempt a token review on the incoming request, if
// enabled.
func (p *Proxy) withTokenReview(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// If token review is not enabled then error.
		if !p.config.TokenReview {
			p.handleError(rw, req, errUnauthorized)
			return
		}

		// Attempt to passthrough request if valid token
		if !p.reviewToken(rw, req) {
			// Token review failed so error
			p.handleError(rw, req, errUnauthorized)
			return
		}

		// Set no impersonation headers and re-add removed headers.
		req = context.WithNoImpersonation(req)

		handler.ServeHTTP(rw, req)
	})
}

// withLDAPRefresh serves the endpoint that triggers a rebuild of the LDAP user
// to group mapping. It sits after authentication in the chain,
// so only authenticated users can trigger a refresh. The path is not a valid
// API server path, so it can never shadow a request meant for Kubernetes.
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

		klog.V(2).Infof("LDAP refresh requested by %q (%s)",
			requester.GetName(), remoteAddr)

		if err := p.ldapDirectory.Refresh(); err != nil {
			klog.Errorf("failed to refresh LDAP mapping (%s): %s", remoteAddr, err)
			http.Error(rw, "Failed to refresh LDAP mapping", http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(rw).Encode(p.ldapDirectory.Stats()); err != nil {
			klog.Errorf("failed to write LDAP refresh response (%s): %s", remoteAddr, err)
		}
	})
}

// augmentGroups replaces the groups of the given user with the groups they
// hold in the LDAP directories.
func (p *Proxy) augmentGroups(u user.Info, remoteAddr string) user.Info {
	groups, ok := p.ldapDirectory.Groups(u.GetName())
	if !ok {
		if p.ldapDirectory.FallbackToTokenGroups() {
			klog.V(4).Infof("user %q not found in LDAP, falling back to token groups (%s)",
				u.GetName(), remoteAddr)
			return u
		}

		klog.V(4).Infof("user %q not found in LDAP, dropping token groups (%s)",
			u.GetName(), remoteAddr)
	}

	return &authuser.DefaultInfo{
		Name:   u.GetName(),
		UID:    u.GetUID(),
		Groups: groups,
		Extra:  u.GetExtra(),
	}
}

// withImpersonateRequest adds the impersonation request handler to the chain.
func (p *Proxy) withImpersonateRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// If no impersonation has already been set, return early
		if context.NoImpersonation(req) {
			handler.ServeHTTP(rw, req)
			return
		}

		var targetForContext user.Info
		targetForContext = nil

		var remoteAddr string
		req, remoteAddr = context.RemoteAddr(req)

		// If we have disabled impersonation we can forward the request right away
		if p.config.DisableImpersonation {
			klog.V(2).Infof("passing on request with no impersonation: %s", remoteAddr)
			// Indicate we need to not use impersonation.
			req = context.WithNoImpersonation(req)
			handler.ServeHTTP(rw, req)
			return
		}

		user, ok := genericapirequest.UserFrom(req.Context())
		// No name available so reject request
		if !ok || len(user.GetName()) == 0 {
			p.handleError(rw, req, errNoName)
			return
		}

		// Keep the name from the token but take the groups from the directory.
		// This happens before the impersonation check below so that the
		// authorization decision is made against the directory groups too.
		if p.ldapDirectory != nil {
			user = p.augmentGroups(user, remoteAddr)
		}

		userForContext := user

		if p.hasImpersonation(req.Header) {
			// if impersonation headers are present, let's check to see
			// if the user is authorized to perform the impersonation
			target, err := p.subjectAccessReviewer.CheckAuthorizedForImpersonation(req, user)

			if err != nil {
				p.handleError(rw, req, err)
				return
			}

			if target != nil {
				// TODO - store original context for logging
				user = target
				targetForContext = target
			}
		}

		// Ensure group contains allauthenticated builtin
		allAuthFound := false
		groups := user.GetGroups()
		for _, elem := range groups {
			if elem == authuser.AllAuthenticated {
				allAuthFound = true
				break
			}
		}
		if !allAuthFound {
			groups = append(groups, authuser.AllAuthenticated)
		}

		extra := user.GetExtra()

		if extra == nil {
			extra = make(map[string][]string)
		}

		// If client IP user extra header option set then append the remote client
		// address.
		if p.config.ExtraUserHeadersClientIPEnabled {
			klog.V(6).Infof("adding impersonate extra user header %s: %s (%s)",
				UserHeaderClientIPKey, remoteAddr, remoteAddr)

			extra[UserHeaderClientIPKey] = append(extra[UserHeaderClientIPKey], remoteAddr)
		}

		// Add custom extra user headers to impersonation request.
		for k, vs := range p.config.ExtraUserHeaders {
			for _, v := range vs {
				klog.V(6).Infof("adding impersonate extra user header %s: %s (%s)",
					k, v, remoteAddr)

				extra[k] = append(extra[k], v)
			}
		}

		if targetForContext != nil {
			// add the original user's information as extra headers
			// so they're recorded in the API server's audit log
			extra["originaluser.jetstack.io-user"] = []string{userForContext.GetName()}

			numGroups := len(userForContext.GetGroups())
			if numGroups > 0 {
				groupNames := make([]string, numGroups)
				for i, groupName := range userForContext.GetGroups() {
					groupNames[i] = groupName
				}

				extra["originaluser.jetstack.io-groups"] = groupNames
			}

			if userForContext.GetUID() != "" {
				extra["originaluser.jetstack.io-uid"] = []string{userForContext.GetUID()}
			}

			if userForContext.GetExtra() != nil && len(userForContext.GetExtra()) > 0 {
				jsonExtras, errJsonMarshal := json.Marshal(userForContext.GetExtra())
				if errJsonMarshal != nil {
					p.handleError(rw, req, errJsonMarshal)
					return
				}
				extra["originaluser.jetstack.io-extra"] = []string{string(jsonExtras)}
			}
		}

		conf := &context.ImpersonationRequest{
			ImpersonationConfig: &transport.ImpersonationConfig{
				UserName: user.GetName(),
				Groups:   groups,
				Extra:    extra,
			},
			InboundUser:      &userForContext,
			ImpersonatedUser: &targetForContext,
		}

		// Add the impersonation configuration to the context.
		req = context.WithImpersonationConfig(req, conf)
		handler.ServeHTTP(rw, req)
	})
}

// newErrorHandler returns a handler failed requests.
func (p *Proxy) newErrorHandler() func(rw http.ResponseWriter, r *http.Request, err error) {

	unauthedHandler := audit.NewUnauthenticatedHandler(p.auditor, func(rw http.ResponseWriter, r *http.Request) {
		klog.V(2).Infof("unauthenticated user request %s", r.RemoteAddr)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	})

	return func(rw http.ResponseWriter, r *http.Request, err error) {

		if err == nil {
			klog.Error("error was called with no error")
			http.Error(rw, "", http.StatusInternalServerError)
			return
		}

		// regardless of reason, log failed auth
		logging.LogFailedRequest(r)

		switch err {

		// Failed auth
		case errUnauthorized:
			// If Unauthorized then error and report to audit
			unauthedHandler.ServeHTTP(rw, r)
			return

			// No name given or available in oidc request
		case errNoName:
			klog.V(2).Infof("no name available in oidc info %s", r.RemoteAddr)
			http.Error(rw, "Username claim not available in OIDC Issuer response", http.StatusForbidden)
			return

			// No impersonation configuration found in context
		case errNoImpersonationConfig:
			klog.Errorf("if you are seeing this, there is likely a bug in the proxy (%s): %s", r.RemoteAddr, err)
			http.Error(rw, "", http.StatusInternalServerError)
			return

			// No impersonation user found
		case subjectaccessreview.ErrorNoImpersonationUserFound:
			http.Error(rw, subjectaccessreview.ErrorNoImpersonationUserFound.Error(), http.StatusInternalServerError)
			return

			// Server or unknown error
		default:

			if strings.Contains(err.Error(), "not allowed to impersonate") {
				klog.V(2).Infof(err.Error(), r.RemoteAddr)
				http.Error(rw, err.Error(), http.StatusForbidden)
			} else {
				klog.Errorf("unknown error (%s): %s", r.RemoteAddr, err)
				http.Error(rw, "", http.StatusInternalServerError)
			}

		}
	}
}

func (p *Proxy) hasImpersonation(header http.Header) bool {
	for h := range header {
		if strings.HasPrefix(strings.ToLower(h), "impersonate-") {
			return true
		}
	}

	return false
}
