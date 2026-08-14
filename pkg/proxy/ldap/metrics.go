// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricsNamespace = "kube_oidc_proxy_ldap"

	duplicateKindUser  = "user"
	duplicateKindGroup = "group"
)

var (
	// lastRefreshSuccess is 1 when the mapping being served is the one this
	// proxy last went and got, and 0 when the attempt failed and the mapping
	// is therefore older than it should be. Going and getting it means a
	// rebuild from the directories, or - on a reader, which does not rebuild
	// anything - picking up what the builder published.
	//
	// Failing is not itself an outage in either case: the previous mapping
	// keeps serving, so nothing surfaces it to a request. This is what an
	// operator alerts on to find out that group changes have stopped being
	// picked up.
	lastRefreshSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "last_refresh_success",
		Help: "1 if the mapping being served is the one this proxy last went and got - rebuilt, " +
			"or picked up from the builder - and 0 if that failed.",
	})

	// backendDuplicateValues is 1 for a backend whose last rebuild found two
	// entries claiming one username or emitted group name. Either fails the
	// rebuild, so it is a directory to fix rather than a transient condition.
	// Each kind stays set until a rebuild gets through its corresponding search.
	backendDuplicateValues = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "backend_duplicate_values",
		Help:      "1 if two entries of this backend claim one user or group authorization value, which fails the rebuild.",
	}, []string{"backend", "kind"})

	// refreshDuration and backendRefreshDuration record only rebuilds that
	// succeeded. A rebuild that failed is mostly a measure of how long it took
	// to give up - a connection timing out, say - which would drag the
	// distribution somewhere that says nothing about how long the work takes.
	// That a rebuild failed at all is what last_refresh_success is for.
	refreshDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "refresh_duration_seconds",
		Help:      "How long a complete rebuild of the mapping took, across every backend.",
		Buckets:   refreshBuckets,
	})

	backendRefreshDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "backend_refresh_duration_seconds",
		Help:      "How long searching one backend took during a rebuild.",
		Buckets:   refreshBuckets,
	}, []string{"backend"})
)

// refreshBuckets runs from 100ms to a little over three minutes. Rebuilding a
// mapping reads every user and every group of a directory, so it is measured in
// seconds on a small directory and in minutes on a large one, and the default
// buckets - which stop at ten seconds - would put almost everything in the
// overflow.
var refreshBuckets = prometheus.ExponentialBuckets(0.1, 2, 12)

// registerMetrics publishes the metrics on first use, so that a proxy running
// without LDAP augmentation configured reports no series at all rather than a
// last_refresh_success of 0 that nothing will ever set. Registering once keeps
// building more than one Directory, as the tests do, from panicking.
var registerMetrics = sync.OnceFunc(func() {
	prometheus.MustRegister(lastRefreshSuccess, backendDuplicateValues,
		refreshDuration, backendRefreshDuration)
})
