package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func userTestDirectory(t *testing.T) (*UserDirectory, *fake.Clientset) {
	t.Helper()
	config := testConfig()
	config.Cache = &CacheConfig{Type: CacheTypeNone, Namespace: "proxy", Scope: "main"}
	client := fake.NewClientset()
	store, err := cache.NewConfigMaps(client, "proxy", "main", config.UserRecordFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewUserDirectory(config, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.cancel)
	return d, client
}

func userTestEntry(t *testing.T, d *UserDirectory, version string, groups ...string) cache.UserEntry {
	t.Helper()
	record, err := d.resolver.config.NewUserRecord("alice", true, groups, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	name, _ := cache.UserConfigMapName("main", "alice")
	return cache.UserEntry{Name: name, ResourceVersion: version, Record: record}
}

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
	if !d.HasMapping() {
		t.Fatal("empty cache is not ready")
	}
	e := userTestEntry(t, d, "10", "Developers")
	data, _ := cache.EncodeUserRecord(e.Record)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: e.Name, Namespace: "proxy", ResourceVersion: "10", Labels: map[string]string{cache.ManagedLabel: "kube-oidc-proxy", cache.ScopeLabel: "main"}}, Data: map[string]string{cache.UserRecordKey: string(data)}}
	if _, err := client.CoreV1().ConfigMaps("proxy").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	await := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := d.cached("alice"); ok == want {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("cache present != %v", want)
	}
	await(true)
	cm.ResourceVersion = "11"
	if _, err := client.CoreV1().ConfigMaps("proxy").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Fake deletion retains the object's version; real API deletions advance it.
	if err := client.CoreV1().ConfigMaps("proxy").Delete(context.Background(), e.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	await(false)
}
