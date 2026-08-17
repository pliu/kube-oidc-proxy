// Copyright Jetstack Ltd. See LICENSE for details.
package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// The requests that stream are recognised from the paths kubectl actually
// sends, rather than from a RequestInfo built by hand, so that a change in how
// a path is taken apart cannot leave the check passing while the audit log goes
// quiet for the whole of an exec session.
func TestRequestsThatStreamAreTreatedAsLongRunning(t *testing.T) {
	resolver := &apirequest.RequestInfoFactory{
		APIPrefixes:          sets.NewString("api", "apis"),
		GrouplessAPIPrefixes: sets.NewString("api"),
	}

	tests := map[string]struct {
		method      string
		path        string
		longRunning bool
	}{
		"exec into a pod": {
			http.MethodPost, "/api/v1/namespaces/ns/pods/p/exec?container=c&command=sh", true,
		},
		"attach to a pod": {
			http.MethodPost, "/api/v1/namespaces/ns/pods/p/attach?container=c", true,
		},
		"port forward to a pod": {
			http.MethodPost, "/api/v1/namespaces/ns/pods/p/portforward", true,
		},
		"following the logs of a pod": {
			http.MethodGet, "/api/v1/namespaces/ns/pods/p/log?follow=true", true,
		},
		// The subresource decides this, not the follow parameter, so reading
		// the logs once is treated the same way. That costs an extra audit
		// event for a request that was going to end promptly anyway, which is
		// the cheaper way to be wrong.
		"reading the logs of a pod once": {
			http.MethodGet, "/api/v1/namespaces/ns/pods/p/log", true,
		},
		"watching a list of pods": {
			http.MethodGet, "/api/v1/namespaces/ns/pods?watch=true", true,
		},
		"proxying to a service": {
			http.MethodGet, "/api/v1/namespaces/ns/services/s/proxy/", true,
		},

		"getting a pod": {
			http.MethodGet, "/api/v1/namespaces/ns/pods/p", false,
		},
		"listing pods": {
			http.MethodGet, "/api/v1/namespaces/ns/pods", false,
		},
		"creating a deployment": {
			http.MethodPost, "/apis/apps/v1/namespaces/ns/deployments", false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, nil)

			info, err := resolver.NewRequestInfo(req)
			if err != nil {
				t.Fatalf("failed to resolve the request info of %s: %s", test.path, err)
			}

			if got := longRunningRequests(req, info); got != test.longRunning {
				t.Errorf("expected %s to be reported as long-running=%v, got %v",
					test.path, test.longRunning, got)
			}
		})
	}
}
