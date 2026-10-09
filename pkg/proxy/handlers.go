// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"errors"
	"net/http"
	"strings"

	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/logging"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/jetstack/kube-oidc-proxy/pkg/util"
)

// errImpersonationNotAccepted is returned for a request that carries
// Impersonate- headers. See withImpersonateRequest for why they are refused.
var errImpersonationNotAccepted = errors.New("impersonation headers are not accepted")

// errReservedUsername is returned for a token whose username is one Kubernetes
// reserves. See isReservedUsername.
var errReservedUsername = errors.New("usernames starting with system: are not accepted")

func (p *Proxy) withHandlers(handler http.Handler) http.Handler {
	// Set up proxy handlers
	handler = p.auditor.WithRequest(handler)
	handler = p.withImpersonateRequest(handler)
	handler = p.withLDAPRefresh(handler)
	handler = p.withAuthenticateRequest(handler)
	handler = p.withRequestCount(handler)

	return handler
}

// withAuthenticateRequest adds the proxy authentication handler to a chain.
func (p *Proxy) withAuthenticateRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Passthrough leaves authentication to the API server, which the
		// request reaches as it is, carrying the caller's own token. Only a
		// request with no token at all is turned away here, as every path does.
		if p.config.TokenPassthrough {
			if _, ok := util.ParseTokenFromRequest(req); !ok {
				p.handleError(rw, req, errUnauthorized)
				return
			}

			handler.ServeHTTP(rw, req)
			return
		}

		// Auth request and handle unauthed
		info, ok, err := p.oidcRequestAuther.AuthenticateRequest(req)
		if err != nil {
			klog.V(5).Infof("Authenticated request failed: %s", err)
			p.handleError(rw, req, errUnauthorized)
			return
		}

		// Failed authorization
		if !ok {
			p.handleError(rw, req, errUnauthorized)
			return
		}

		var remoteAddr string
		req, remoteAddr = reqctx.RemoteAddr(req)

		if isReservedUsername(info.User.GetName()) {
			klog.V(2).Infof("rejecting token with reserved username %q (%s)",
				info.User.GetName(), remoteAddr)
			p.handleError(rw, req, errReservedUsername)
			return
		}

		klog.V(4).Infof("authenticated request: %s", remoteAddr)

		// Add the user info to the request context
		req = req.WithContext(genericapirequest.WithUser(req.Context(), withoutReservedGroups(info.User, remoteAddr)))
		handler.ServeHTTP(rw, req)
	})
}

// withImpersonateRequest adds the impersonation request handler to the chain.
func (p *Proxy) withImpersonateRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// A passthrough request is forwarded as it is, Impersonate- headers
		// included: it carries the caller's own token, so the API server holds
		// the caller to their own impersonation rights.
		if p.config.TokenPassthrough {
			handler.ServeHTTP(rw, req)
			return
		}

		var remoteAddr string
		req, remoteAddr = reqctx.RemoteAddr(req)

		requester, ok := genericapirequest.UserFrom(req.Context())
		// No name available so reject request
		if !ok || len(requester.GetName()) == 0 {
			p.handleError(rw, req, errNoName)
			return
		}

		// A request may not ask to act as somebody else. The proxy forwards with
		// its own credentials, which may impersonate anyone, so the API server
		// never sees who is really asking and cannot hold them to their own
		// impersonation rights. The request runs as the identity of its token,
		// with the groups of its token or of the directory, and nothing else.
		//
		// This is refused rather than ignored. A caller that asked to act as
		// somebody else and is quietly served as themselves has been told the
		// wrong thing about who did the work - kubectl auth can-i --as would
		// answer for the wrong user.
		if hasImpersonation(req.Header) {
			klog.V(2).Infof("rejecting impersonation headers from %q (%s)",
				requester.GetName(), remoteAddr)
			p.handleError(rw, req, errImpersonationNotAccepted)
			return
		}

		// Keep the name from the token but take the groups from the directory.
		if p.ldapDirectory != nil {
			var err error
			requester, err = p.augmentGroups(req.Context(), requester)
			if err != nil {
				klog.Errorf("LDAP group resolution failed (%s): %v", remoteAddr, err)
				http.Error(rw, "Group resolution unavailable", http.StatusServiceUnavailable)
				return
			}

			// The audit event is built from the identity the context holds
			// when the auditor runs, which is inside this handler. Left as the
			// identity authentication put there, it would record the groups of
			// the token rather than the groups the request is actually run
			// with - the audit log of a proxy that exists in order not to
			// trust the groups of a token would be recording exactly those.
			req = req.WithContext(genericapirequest.WithUser(req.Context(), requester))
		}

		conf := buildImpersonation(requester, remoteAddr, p.config)

		// Add the impersonation configuration to the context.
		req = reqctx.WithImpersonationConfig(req, conf)
		handler.ServeHTTP(rw, req)
	})
}

// newErrorHandler returns a handler failed requests.
func (p *Proxy) newErrorHandler() func(rw http.ResponseWriter, r *http.Request, err error) {

	unauthedHandler := p.auditor.WithUnauthorized(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		klog.V(2).Infof("unauthenticated user request %s", r.RemoteAddr)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	}))

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

			// Impersonation headers, which are never honoured
		case errImpersonationNotAccepted:
			http.Error(rw, errImpersonationNotAccepted.Error(), http.StatusForbidden)
			return

			// A token naming an identity Kubernetes reserves
		case errReservedUsername:
			http.Error(rw, errReservedUsername.Error(), http.StatusForbidden)
			return

			// No impersonation configuration found in context
		case errNoImpersonationConfig:
			klog.Errorf("if you are seeing this, there is likely a bug in the proxy (%s): %s", r.RemoteAddr, err)
			http.Error(rw, "", http.StatusInternalServerError)
			return

			// Server or unknown error
		default:
			klog.Errorf("unknown error (%s): %s", r.RemoteAddr, err)
			http.Error(rw, "", http.StatusInternalServerError)
		}
	}
}

// hasImpersonation reports whether a request carries any header of the
// Impersonate-* family, matched case insensitively. Any one of them, known to
// Kubernetes or not, is a request to act as somebody else.
func hasImpersonation(header http.Header) bool {
	for h := range header {
		if isImpersonationHeader(h) {
			return true
		}
	}

	return false
}

func isImpersonationHeader(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "impersonate-")
}
