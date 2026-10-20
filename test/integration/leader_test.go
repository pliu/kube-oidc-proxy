// Copyright Jetstack Ltd. See LICENSE for details.
package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
)

func waitForLeader(t *testing.T, apiURL string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(apiURL + "/apis/coordination.k8s.io/v1/namespaces/proxy/leases/kube-oidc-proxy")
		if err == nil {
			var lease coordinationv1.Lease
			err = json.NewDecoder(resp.Body).Decode(&lease)
			resp.Body.Close()
			if err == nil && resp.StatusCode == http.StatusOK && lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy did not acquire the leader election Lease")
}
