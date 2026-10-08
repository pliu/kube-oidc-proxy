// Copyright Jetstack Ltd. See LICENSE for details.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

// serveLease implements the Lease operations used by leader election, including
// resource-version conflicts, while other requests retain the echo behavior.
func (s *Server) serveLease(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 || len(parts) > 7 || parts[0] != "apis" || parts[1] != "coordination.k8s.io" || parts[2] != "v1" || parts[3] != "namespaces" || parts[5] != "leases" {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	encode := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	fail := func(code int, reason metav1.StatusReason) {
		w.WriteHeader(code)
		encode(&metav1.Status{Status: "Failure", Reason: reason, Code: int32(code)})
	}
	key := r.URL.Path
	if r.Method == http.MethodGet && len(parts) == 7 {
		if lease, ok := s.leases[key]; ok {
			encode(lease)
		} else {
			fail(http.StatusNotFound, metav1.StatusReasonNotFound)
		}
		return true
	}
	if (r.Method != http.MethodPost || len(parts) != 6) && (r.Method != http.MethodPut || len(parts) != 7) {
		fail(http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed)
		return true
	}
	body, err := io.ReadAll(r.Body)
	var lease coordinationv1.Lease
	if err == nil {
		_, _, err = scheme.Codecs.UniversalDeserializer().Decode(body, nil, &lease)
	}
	if err != nil {
		fail(http.StatusBadRequest, metav1.StatusReasonBadRequest)
		return true
	}
	if r.Method == http.MethodPost {
		key += "/" + lease.Name
	}
	old, exists := s.leases[key]
	if r.Method == http.MethodPost && exists {
		fail(http.StatusConflict, metav1.StatusReasonAlreadyExists)
		return true
	}
	if r.Method == http.MethodPut {
		if !exists {
			fail(http.StatusNotFound, metav1.StatusReasonNotFound)
			return true
		}
		if lease.ResourceVersion != old.ResourceVersion {
			fail(http.StatusConflict, metav1.StatusReasonConflict)
			return true
		}
	}
	var version int
	_, _ = fmt.Sscan(old.ResourceVersion, &version)
	lease.ResourceVersion = fmt.Sprint(version + 1)
	lease.Namespace = parts[4]
	lease.APIVersion = "coordination.k8s.io/v1"
	lease.Kind = "Lease"
	s.leases[key] = lease
	if r.Method == http.MethodPost {
		w.WriteHeader(http.StatusCreated)
	}
	encode(lease)
	return true
}
