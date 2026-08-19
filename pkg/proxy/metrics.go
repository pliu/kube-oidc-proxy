// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/felixge/httpsnoop"
	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "kube_oidc_proxy"

// requestsTotal counts completed requests by the HTTP response code returned
// to the client. The code label is bounded by the status codes a handler can
// emit and contains no request or identity data.
var requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: metricsNamespace,
	Name:      "requests_total",
	Help:      "Total number of completed requests, labeled by HTTP response code.",
}, []string{"code"})

// registerMetrics publishes the metrics on first use. Registering once keeps
// building more than one Proxy, as the tests do, from panicking.
var registerMetrics = sync.OnceFunc(func() {
	prometheus.MustRegister(requestsTotal)
})

// withRequestCount counts requests when their handlers return. It sits
// outermost, so that it sees responses rejected by authentication as well as
// responses from the upstream API server. httpsnoop preserves the exact set of
// optional interfaces implemented by the underlying ResponseWriter, including
// the interfaces used by exec and port-forward upgrades.
func (p *Proxy) withRequestCount(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		var responseCode atomic.Int32
		record := func(code int) {
			responseCode.CompareAndSwap(0, int32(code))
		}

		wrapped := httpsnoop.Wrap(rw, httpsnoop.Hooks{
			WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) {
					// Informational responses do not decide the request's final
					// status. Switching Protocols is the exception: it is the
					// final response for exec, attach, and port-forward upgrades.
					if code == http.StatusSwitchingProtocols || code < 100 || code >= 200 {
						record(code)
					}

					next(code)
				}
			},
			Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(body []byte) (int, error) {
					record(http.StatusOK)
					return next(body)
				}
			},
			ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return func(src io.Reader) (int64, error) {
					record(http.StatusOK)
					return next(src)
				}
			},
			Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
				return func() (net.Conn, *bufio.ReadWriter, error) {
					conn, buffered, err := next()
					if err == nil {
						// ReverseProxy writes an upgrade response directly to the
						// hijacked connection, bypassing WriteHeader entirely.
						record(http.StatusSwitchingProtocols)
					}

					return conn, buffered, err
				}
			},
		})

		defer func() {
			code := responseCode.Load()
			if code == 0 {
				code = http.StatusOK
			}

			requestsTotal.WithLabelValues(strconv.Itoa(int(code))).Inc()
		}()

		handler.ServeHTTP(wrapped, req)
	})
}
