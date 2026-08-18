// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"
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
	handler = p.withRequestCount(handler)

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

// withImpersonateRequest adds the impersonation request handler to the chain.
func (p *Proxy) withImpersonateRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// If no impersonation has already been set, return early
		if context.NoImpersonation(req) {
			handler.ServeHTTP(rw, req)
			return
		}

		var targetForContext user.Info

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

		requester, ok := genericapirequest.UserFrom(req.Context())
		// No name available so reject request
		if !ok || len(requester.GetName()) == 0 {
			p.handleError(rw, req, errNoName)
			return
		}

		// A request may not both ask to be impersonated as somebody else and
		// have its groups decided by the directory. Honouring the headers
		// builds the target identity out of Impersonate-Group alone, so the
		// caller - not the directory - would decide the groups the request runs
		// with, which is the thing augmentation exists to stop. Even
		// Impersonate-User on its own runs the target as a member of no groups
		// rather than of the groups the directory holds for them.
		//
		// This is refused rather than ignored. A caller that asked to act as
		// somebody else and is quietly served as themselves has been told the
		// wrong thing about who did the work.
		if p.ldapDirectory != nil && p.hasImpersonation(req.Header) {
			klog.V(2).Infof("rejecting impersonation headers from %q while groups are taken from the directory (%s)",
				requester.GetName(), remoteAddr)
			p.handleError(rw, req, errImpersonationNotAccepted)
			return
		}

		// Keep the name from the token but take the groups from the directory.
		// This happens before the impersonation check below so that the
		// authorization decision is made against the directory groups too.
		if p.ldapDirectory != nil {
			requester = p.augmentGroups(requester, remoteAddr)

			// The audit event is built from the identity the context holds
			// when the auditor runs, which is inside this handler. Left as the
			// identity authentication put there, it would record the groups of
			// the token rather than the groups the request is actually run
			// with - the audit log of a proxy that exists in order not to
			// trust the groups of a token would be recording exactly those.
			req = req.WithContext(genericapirequest.WithUser(req.Context(), requester))
		}

		// requester stays the inbound identity. effective is who the request
		// actually runs as: the requester, or the impersonation target if one
		// was authorised.
		effective := requester

		if p.hasImpersonation(req.Header) {
			// if impersonation headers are present, let's check to see
			// if the user is authorized to perform the impersonation
			target, err := p.subjectAccessReviewer.CheckAuthorizedForImpersonation(req, requester)

			if err != nil {
				p.handleError(rw, req, err)
				return
			}

			if target != nil {
				// TODO - store original context for logging
				effective = target
				targetForContext = target
			}
		}

		// Ensure group contains allauthenticated builtin
		allAuthFound := false
		groups := effective.GetGroups()
		for _, elem := range groups {
			if elem == user.AllAuthenticated {
				allAuthFound = true
				break
			}
		}
		if !allAuthFound {
			groups = append(groups, user.AllAuthenticated)
		}

		extra := effective.GetExtra()

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
			extra["originaluser.jetstack.io-user"] = []string{requester.GetName()}

			numGroups := len(requester.GetGroups())
			if numGroups > 0 {
				groupNames := make([]string, numGroups)
				for i, groupName := range requester.GetGroups() {
					groupNames[i] = groupName
				}

				extra["originaluser.jetstack.io-groups"] = groupNames
			}

			if requester.GetUID() != "" {
				extra["originaluser.jetstack.io-uid"] = []string{requester.GetUID()}
			}

			if requester.GetExtra() != nil && len(requester.GetExtra()) > 0 {
				jsonExtras, errJsonMarshal := json.Marshal(requester.GetExtra())
				if errJsonMarshal != nil {
					p.handleError(rw, req, errJsonMarshal)
					return
				}
				extra["originaluser.jetstack.io-extra"] = []string{string(jsonExtras)}
			}
		}

		conf := &context.ImpersonationRequest{
			ImpersonationConfig: &transport.ImpersonationConfig{
				UserName: effective.GetName(),
				Groups:   groups,
				Extra:    extra,
			},
			InboundUser:      &requester,
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

			// Impersonation headers sent while the groups of a request are
			// taken from the directory
		case errImpersonationNotAccepted:
			http.Error(rw, errImpersonationNotAccepted.Error(), http.StatusForbidden)
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
