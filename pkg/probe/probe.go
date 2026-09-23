// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/heptiolabs/healthcheck"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"
)

type HealthCheck struct {
	handler healthcheck.Handler

	// oidcHealth returns an error until the OIDC authenticator of every
	// trusted issuer has finished initialising.
	oidcHealth func() error

	// oidcReady is sticky once the OIDC authenticators have finished
	// initialising. The provider being reachable later is not required for
	// serving, and probing it again would flap readiness when the issuer
	// blips.
	oidcReady atomic.Bool

	// serving is set once the secure listener is accepting connections.
	// Without this, a restored LDAP mapping (or an initialised OIDC
	// authenticator) would report the pod Ready while Run is still blocked
	// on the first directory sweep and nothing is accepting on the bound
	// port. The port is bound long before then, so a connection would be
	// taken and the request left hanging rather than refused.
	serving atomic.Bool
}

// NamedCheck is a readiness check beyond the ones the proxy always makes. It
// is published under its own name, so that a pod sitting out of its Service
// says which condition it is waiting on rather than only that it is not ready.
type NamedCheck struct {
	Name  string
	Check func() error
}

func Run(port string, oidcHealth func() error, checks ...NamedCheck) *HealthCheck {
	h := &HealthCheck{
		handler:    healthcheck.NewHandler(),
		oidcHealth: oidcHealth,
	}

	h.handler.AddReadinessCheck("secure serving", h.Check)

	for _, check := range checks {
		h.handler.AddReadinessCheck(check.Name, check.Check)
	}

	// Metrics are served beside the probes rather than on the secure port,
	// where every path that is not handled by the proxy itself is forwarded to
	// the API server, and where a scraper would need a token the OIDC issuer
	// accepts. They carry no request data, only counts and the names of the
	// configured LDAP backends.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/", h.handler)

	go func() {
		for {
			err := http.ListenAndServe(net.JoinHostPort("0.0.0.0", port), mux)
			if err != nil {
				klog.Errorf("ready probe listener failed: %s", err)
			}
			time.Sleep(5 * time.Second)
		}
	}()

	return h
}

// MarkServing records that the secure listener is accepting connections.
// Until this is called the pod stays unready, even if every other check has
// already passed.
func (h *HealthCheck) MarkServing() {
	h.serving.Store(true)
	klog.V(4).Info("secure listener is serving")
}

func (h *HealthCheck) Check() error {
	if !h.oidcReady.Load() {
		if err := h.oidcHealth(); err != nil {
			err = fmt.Errorf("OIDC provider not yet initialized: %s", err)
			klog.V(4).Infof("%v", err.Error())
			return err
		}

		h.oidcReady.Store(true)

		klog.V(4).Info("OIDC provider initialized.")
	}

	if !h.serving.Load() {
		return errors.New("secure listener is not serving yet")
	}

	return nil
}
