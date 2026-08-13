// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "kube_oidc_proxy"

// requestsTotal counts every request the proxy is handed, before any of them
// have been authenticated, so that requests being rejected shows up as
// requests arriving rather than as silence.
var requestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: metricsNamespace,
	Name:      "requests_total",
	Help:      "Total number of requests received, counted before authentication.",
})

// registerMetrics publishes the metrics on first use. Registering once keeps
// building more than one Proxy, as the tests do, from panicking.
var registerMetrics = sync.OnceFunc(func() {
	prometheus.MustRegister(requestsTotal)
})

// withRequestCount counts requests as they arrive. It sits outermost, so that
// it sees requests an inner handler rejects as well as those it serves.
//
// The response is deliberately left alone. Counting by status code would mean
// wrapping the ResponseWriter for every request, including the ones that get
// hijacked for exec and port forward, and a count of requests is not worth
// putting a wrapper in the way of those.
func (p *Proxy) withRequestCount(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		requestsTotal.Inc()

		handler.ServeHTTP(rw, req)
	})
}
