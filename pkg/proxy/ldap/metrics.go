// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "kube_oidc_proxy_ldap"

var (
	// Failed refreshes retain old memberships; this gauge surfaces failures.
	lastRefreshSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "last_refresh_success",
		Help:      "1 if the last cached-user refresh cycle succeeded, and 0 if any user failed.",
	})

	refreshDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "refresh_duration_seconds",
		Help:      "Duration of a cached-user refresh cycle, including failed cycles.",
		Buckets:   refreshBuckets,
	})

	backendRefreshDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "backend_refresh_duration_seconds",
		Help:      "Duration of a successful single-user lookup against one backend.",
		Buckets:   refreshBuckets,
	}, []string{"backend"})
)

var refreshBuckets = prometheus.ExponentialBuckets(0.1, 2, 12)

// registerMetrics publishes the metrics on first use, so that a proxy running
// without LDAP augmentation configured reports no series at all rather than a
// last_refresh_success of 0 that nothing will ever set. Registering once keeps
// building more than one Directory, as the tests do, from panicking.
var registerMetrics = sync.OnceFunc(func() {
	prometheus.MustRegister(lastRefreshSuccess, refreshDuration,
		backendRefreshDuration)
})
