// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"fmt"
	"net/http"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
	"k8s.io/apimachinery/pkg/util/sets"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/server"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	"k8s.io/component-base/compatibility"
	"k8s.io/component-base/version"
)

type Audit struct {
	opts         *options.AuditOptions
	serverConfig *server.CompletedConfig
}

// longRunningRequests reports whether a request is one that streams for as long
// as the caller keeps it open, rather than one that is answered and finished
// with.
//
// This decides when the audit log hears about a request. A request that is not
// long-running is recorded once, when it completes, which is the right thing
// for a request that completes promptly. A long-running one is recorded twice:
// once when the response starts and again when the stream finally ends. Getting
// this wrong for a stream means an exec session that lasts an hour leaves
// nothing in the audit log for that hour, and leaves nothing at all if the
// proxy is killed before the session ends - exactly the requests an audit log
// is most wanted for.
//
// The generic apiserver default treats only watch this way, on the grounds that
// a generic API server has no inherent long-running subresources. That default
// is wrong here: everything this proxy forwards goes to a kube-apiserver, so
// the set that kube-apiserver itself uses is the set that applies.
var longRunningRequests = genericfilters.BasicLongRunningRequestCheck(
	sets.NewString("watch", "proxy"),
	sets.NewString("attach", "exec", "proxy", "log", "portforward"),
)

// New creates a new Audit struct to handle auditing for proxy requests. This
// is mostly a wrapper for the apiserver auditing handlers to combine them with
// the proxy.
func New(opts *options.AuditOptions, externalAddress string, secureServingInfo *server.SecureServingInfo) (*Audit, error) {
	serverConfig := &server.Config{
		ExternalAddress: externalAddress,
		SecureServing:   secureServingInfo,

		LongRunningFunc: longRunningRequests,
	}

	// We do not support dynamic auditing, so leave nil
	if err := opts.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	serverConfig.EffectiveVersion = compatibility.NewEffectiveVersionFromString(version.Get().String(), version.Get().String(), version.Get().String())

	completed := serverConfig.Complete(nil)

	return &Audit{
		opts:         opts,
		serverConfig: &completed,
	}, nil
}

// Run will run the audit backend if configured.
func (a *Audit) Run(stopCh <-chan struct{}) error {
	if a.serverConfig.AuditBackend != nil {
		if err := a.serverConfig.AuditBackend.Run(stopCh); err != nil {
			return fmt.Errorf("failed to run the audit backend: %s", err)
		}
	}

	return nil
}

// Shutdown will shutdown the audit backend if configured.
func (a *Audit) Shutdown() error {
	if a.serverConfig.AuditBackend != nil {
		a.serverConfig.AuditBackend.Shutdown()
	}

	return nil
}

// WithRequest will wrap the given handler to inject the request information
// into the context which is then used by the wrapped audit handler.
func (a *Audit) WithRequest(handler http.Handler) http.Handler {
	handler = genericapifilters.WithAudit(handler, a.serverConfig.AuditBackend, a.serverConfig.AuditPolicyRuleEvaluator, a.serverConfig.LongRunningFunc)
	handler = genericapifilters.WithAuditInit(handler)
	return genericapifilters.WithRequestInfo(handler, a.serverConfig.RequestInfoResolver)
}

// WithUnauthorized will wrap the given handler to inject the request
// information into the context which is then used by the wrapped audit
// handler.
func (a *Audit) WithUnauthorized(handler http.Handler) http.Handler {
	handler = genericapifilters.WithFailedAuthenticationAudit(handler, a.serverConfig.AuditBackend, a.serverConfig.AuditPolicyRuleEvaluator)
	return genericapifilters.WithRequestInfo(handler, a.serverConfig.RequestInfoResolver)
}
