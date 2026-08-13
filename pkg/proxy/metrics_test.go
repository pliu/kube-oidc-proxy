// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Requests are counted before authentication, so requests being turned away
// reads as requests arriving rather than as nothing happening at all.
func TestRequestsAreCountedBeforeTheyAreAuthenticated(t *testing.T) {
	before := testutil.ToFloat64(requestsTotal)

	var served int

	p := new(Proxy)
	handler := p.withRequestCount(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		served++
		rw.WriteHeader(http.StatusUnauthorized)
	}))

	for i := 0; i < 3; i++ {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))

		if rw.Code != http.StatusUnauthorized {
			t.Errorf("expected the wrapped handler to still decide the response, got %d", rw.Code)
		}
	}

	if served != 3 {
		t.Errorf("expected the wrapped handler to have served 3 requests, got %d", served)
	}

	if got := testutil.ToFloat64(requestsTotal) - before; got != 3 {
		t.Errorf("expected 3 requests to have been counted, got %v", got)
	}
}
