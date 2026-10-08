// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
)

func TestImpersonationDenialsUseErrorType(t *testing.T) {
	denied := &subjectaccessreview.ImpersonationDeniedError{Requester: "caller", Resource: "users", Name: "target"}
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"denial", denied, http.StatusForbidden},
		{"wrapped denial", fmt.Errorf("authorization: %w", denied), http.StatusForbidden},
		{"unrelated error with identical text", errors.New(denied.Error()), http.StatusInternalServerError},
	}
	p := &Proxy{}
	handler := p.newErrorHandler()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			handler(rw, httptest.NewRequest("GET", "/", nil), tt.err)
			if rw.Code != tt.status {
				t.Fatalf("status=%d want=%d", rw.Code, tt.status)
			}
		})
	}
}
