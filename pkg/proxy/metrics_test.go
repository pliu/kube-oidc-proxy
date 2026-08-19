// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

type hijackableResponseWriter struct {
	*httptest.ResponseRecorder
}

func (*hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

func TestRequestsAreCountedByResponseCode(t *testing.T) {
	p := new(Proxy)

	for _, code := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusInternalServerError} {
		code := code
		before := testutil.ToFloat64(requestsTotal.WithLabelValues(strconv.Itoa(code)))

		handler := p.withRequestCount(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(code)
		}))
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))

		if rw.Code != code {
			t.Errorf("expected the wrapped handler to still decide the response, got %d", rw.Code)
		}

		if got := testutil.ToFloat64(requestsTotal.WithLabelValues(strconv.Itoa(code))) - before; got != 1 {
			t.Errorf("expected one %d response to be counted, got %v", code, got)
		}
	}
}

func TestRequestCountUsesImplicitAndUpgradeResponseCodes(t *testing.T) {
	p := new(Proxy)

	for name, test := range map[string]struct {
		code    int
		handler http.HandlerFunc
	}{
		"implicit success": {
			code: http.StatusOK,
			handler: func(http.ResponseWriter, *http.Request) {
			},
		},
		"protocol upgrade": {
			code: http.StatusSwitchingProtocols,
			handler: func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(http.StatusSwitchingProtocols)
			},
		},
		"provisional then final": {
			code: http.StatusNoContent,
			handler: func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(http.StatusEarlyHints)
				rw.WriteHeader(http.StatusNoContent)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := testutil.ToFloat64(requestsTotal.WithLabelValues(strconv.Itoa(test.code)))

			handler := p.withRequestCount(test.handler)
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))

			if got := testutil.ToFloat64(requestsTotal.WithLabelValues(strconv.Itoa(test.code))) - before; got != 1 {
				t.Errorf("expected one %d response to be counted, got %v", test.code, got)
			}
		})
	}
}

func TestRequestCountPreservesResponseWriterInterfaces(t *testing.T) {
	p := new(Proxy)
	rw := &hijackableResponseWriter{ResponseRecorder: httptest.NewRecorder()}
	before := testutil.ToFloat64(requestsTotal.WithLabelValues(strconv.Itoa(http.StatusSwitchingProtocols)))

	handler := p.withRequestCount(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("expected the wrapped response writer to remain hijackable")
			return
		}
		if _, ok := w.(http.Flusher); !ok {
			t.Error("expected the wrapped response writer to remain flushable")
		}

		if _, _, err := hijacker.Hijack(); err != nil {
			t.Errorf("unexpected hijack error: %s", err)
		}
	}))

	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))

	if got := testutil.ToFloat64(requestsTotal.WithLabelValues(strconv.Itoa(http.StatusSwitchingProtocols))) - before; got != 1 {
		t.Errorf("expected a hijacked request to be counted as 101, got %v", got)
	}
}
