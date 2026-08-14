// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/heptiolabs/healthcheck"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/klog/v2"
)

const (
	timeout = time.Second * 10
)

type HealthCheck struct {
	handler healthcheck.Handler

	oidcAuther authenticator.Token
	fakeJWT    string

	ready bool
}

// NamedCheck is a readiness check beyond the ones the proxy always makes. It
// is published under its own name, so that a pod sitting out of its Service
// says which condition it is waiting on rather than only that it is not ready.
type NamedCheck struct {
	Name  string
	Check func() error
}

func Run(port, fakeJWT string, oidcAuther authenticator.Token, checks ...NamedCheck) error {
	h := &HealthCheck{
		handler:    healthcheck.NewHandler(),
		oidcAuther: oidcAuther,
		fakeJWT:    fakeJWT,
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

	return nil
}

func (h *HealthCheck) Check() error {
	if h.ready {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _, err := h.oidcAuther.AuthenticateToken(ctx, h.fakeJWT)
	if err != nil && strings.HasSuffix(err.Error(), "authenticator not initialized") {
		err = fmt.Errorf("OIDC provider not yet initialized: %s", err)
		klog.V(4).Infof("%v", err.Error())
		return err
	}

	h.ready = true

	klog.V(4).Info("OIDC provider initialized.")

	return nil
}
