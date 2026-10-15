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

	// Only cycles that reach every cached user are observed. A cycle cut short
	// by leadership loss or shutdown did not do a full refresh, and its
	// duration would say nothing about how long one takes.
	fullRefreshDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "full_refresh_duration_seconds",
		Help:      "Duration of a refresh cycle that reached every cached user, including cycles in which some users failed.",
		Buckets:   fullRefreshBuckets,
	})

	// backendRefreshDuration covers one user's refresh against one backend.
	backendRefreshDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "backend_refresh_duration_seconds",
		Help:      "Duration of a successful refresh of one user against one LDAP backend, by trigger: realtime for a request from a user with no cached record, async for the leader's refresh cycle.",
		Buckets:   backendRefreshBuckets,
	}, []string{"backend", "trigger"})

	// backendConnections counts the connections bound to each backend. With
	// connections pooled, it rises with lookups only when they cannot reuse one.
	backendConnections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "backend_connections_total",
		Help:      "Number of connections opened and bound to an LDAP backend.",
	}, []string{"backend"})

	// backendConnectionsClosed counts the connections counted by
	// backendConnections as they close, so the difference is how many are open.
	backendConnectionsClosed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "backend_connections_closed_total",
		Help:      "Number of connections to an LDAP backend closed, by reason: idle or lifetime when the pool retired it, closed_by_server when the directory had already closed it, failed when an operation on it failed, canceled when a lookup was canceled or timed out while using it, pool_full when no idle slot was free, shutdown when the proxy stopped.",
	}, []string{"backend", "reason"})

	// userRefreshFailures counts users whose refresh failed, by what failed. A
	// lookup refused for lack of capacity never started, and one cut short by
	// the replica shutting down did not fail, so neither is counted.
	userRefreshFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "user_refresh_failures_total",
		Help:      "Number of failed refreshes of one user, by source: ldap for the directory, kubernetes for reading or writing the cache ConfigMap.",
	}, []string{"source"})
)

// Values of the source label of userRefreshFailures.
const (
	failureLDAP       = "ldap"
	failureKubernetes = "kubernetes"
)

// Values of the reason label of backendConnectionsClosed.
const (
	closedIdle     = "idle"
	closedLifetime = "lifetime"
	closedByServer = "closed_by_server"
	closedFailed   = "failed"
	closedCanceled = "canceled"
	closedPoolFull = "pool_full"
	closedShutdown = "shutdown"
)

// Values of the trigger label of backendRefreshDuration.
const (
	triggerRealtime = "realtime"
	triggerAsync    = "async"
)

// fullRefreshBuckets run from 100ms to about 3.4 minutes: a cycle refreshes
// every cached user, so takes seconds to minutes.
var fullRefreshBuckets = prometheus.ExponentialBuckets(0.1, 2, 12)

// backendRefreshBuckets run from 1ms to about 33s. Looking one user up in one
// backend takes milliseconds against a nearby directory, connection and bind
// included when no pooled connection is free, and seconds only when the directory is distant or struggling.
var backendRefreshBuckets = prometheus.ExponentialBuckets(0.001, 2, 16)

// registerMetrics publishes the metrics on first use, so that a proxy running
// without LDAP augmentation configured reports no series at all rather than a
// last_refresh_success of 0 that nothing will ever set. Registering once keeps
// constructing multiple resolvers in one process from panicking.
var registerMetrics = sync.OnceFunc(func() {
	prometheus.MustRegister(lastRefreshSuccess, fullRefreshDuration,
		backendRefreshDuration, backendConnections, backendConnectionsClosed, userRefreshFailures)
})
