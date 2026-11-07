// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUserVersionsDoNotRegress(t *testing.T) {
	d, _ := userTestDirectory(t)
	d.apply(userTestEntry(t, d, "20", "new"), false)
	d.apply(userTestEntry(t, d, "19", "old"), false)
	got, ok := d.cached("alice")
	if !ok || got.Record.Groups[0] != "new" {
		t.Fatal(got)
	}
	d.apply(cache.UserEntry{Name: got.Name, ResourceVersion: "21"}, true)
	d.apply(userTestEntry(t, d, "20", "new"), false)
	if _, ok := d.cached("alice"); ok {
		t.Fatal("delayed event resurrected deleted user")
	}
}

func TestUserStartupAndWatch(t *testing.T) {
	d, client := userTestDirectory(t)
	stop := make(chan struct{})
	defer close(stop)
	d.resolver.backends[0].dial = func(string) (conn, error) { t.Error("startup contacted LDAP"); return nil, nil }
	if err := d.Run(stop); err != nil {
		t.Fatal(err)
	}
	if !d.HasSynced() {
		t.Fatal("empty cache is not ready")
	}
	e := userTestEntry(t, d, "10", "Developers")
	data, _ := cache.EncodeUserRecord(e.Record)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: e.Name, Namespace: "proxy", ResourceVersion: "10", Labels: map[string]string{cache.ManagedLabel: "kube-oidc-proxy"}}, Data: map[string]string{cache.UserRecordKey: string(data)}}
	if _, err := client.CoreV1().ConfigMaps("proxy").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	await := func(want bool) {
		t.Helper()
		waitFor(t, fmt.Sprintf("cache present = %v", want), 3*time.Second, func() bool {
			_, ok := d.cached("alice")
			return ok == want
		})
	}
	await(true)
	cm, _ = client.CoreV1().ConfigMaps("proxy").Get(context.Background(), e.Name, metav1.GetOptions{})
	if _, err := client.CoreV1().ConfigMaps("proxy").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Fake deletion retains the object's version; real API deletions advance it.
	if err := client.CoreV1().ConfigMaps("proxy").Delete(context.Background(), e.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	await(false)
}

func TestReplicasLearnCommittedMisses(t *testing.T) {
	first, _ := userTestDirectory(t)
	second := newTestReplica(t, first)
	firstStop, secondStop := make(chan struct{}), make(chan struct{})
	defer close(firstStop)
	defer close(secondStop)
	if err := first.Run(firstStop); err != nil {
		t.Fatal(err)
	}
	if err := second.Run(secondStop); err != nil {
		t.Fatal(err)
	}
	serveUsers(first, map[string][]string{"alice": {"Shared"}})
	if _, err := first.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "replica to learn persisted miss", time.Second, func() bool {
		e, ok := second.cached("alice")
		return ok && e.Record.Groups[0] == "Shared"
	})
}
