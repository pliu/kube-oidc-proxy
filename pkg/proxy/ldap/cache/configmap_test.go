// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestConfigMapRecords(t *testing.T) {
	ctx := context.Background()
	client := fake.NewClientset()
	store, err := NewConfigMaps(client, "proxy", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	record, _ := NewUserRecord("alice", true, []string{"Full Group Name"}, "fingerprint", time.Now())
	if _, err := store.Get(ctx, "alice"); err != ErrNotFound {
		t.Fatal(err)
	}
	saved, err := store.Upsert(ctx, record, "")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Invalid != nil || saved.Record.Groups[0] != "Full Group Name" {
		t.Fatalf("%+v", saved)
	}
	if _, err := store.Upsert(ctx, record, ""); !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create overwrote record: %v", err)
	}
	list, err := store.List(ctx)
	if err != nil || len(list.Entries) != 1 {
		t.Fatalf("%+v %v", list, err)
	}
	cm, _ := client.CoreV1().ConfigMaps("proxy").Get(ctx, saved.Name, metav1.GetOptions{})
	cm.Data[UserRecordKey] = "broken: ["
	if got := store.Decode(cm); got.Invalid == nil || got.Record != nil {
		t.Fatalf("malformed record accepted: %+v", got)
	}
	// Fake API does not enforce resource versions; inject a conflict to verify no retry.
	calls := 0
	client.PrependReactor("update", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		calls++
		return true, nil, apierrors.NewConflict(corev1.Resource("configmaps"), saved.Name, nil)
	})
	if _, err := store.Upsert(ctx, record, "old"); !apierrors.IsConflict(err) || calls != 1 {
		t.Fatalf("%v calls=%d", err, calls)
	}
}

func TestConfigMapDecodePreservesValidationBoundaries(t *testing.T) {
	store, err := NewConfigMaps(fake.NewClientset(), "proxy", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewUserRecord("alice", true, []string{"Developers"}, "fingerprint", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeUserRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	name, err := UserConfigMapName("alice")
	if err != nil {
		t.Fatal(err)
	}
	base := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "42", Labels: map[string]string{ManagedLabel: "kube-oidc-proxy"}}, Data: map[string]string{UserRecordKey: string(data)}}
	if entry := store.Decode(base); entry.Invalid != nil || entry.Record == nil {
		t.Fatalf("valid record rejected: %+v", entry)
	}
	tests := map[string]func(*corev1.ConfigMap){
		"wrong object name": func(cm *corev1.ConfigMap) { cm.Name = "other" },
		"wrong document identity": func(cm *corev1.ConfigMap) {
			cm.Data[UserRecordKey] = strings.Replace(string(data), "username: alice", "username: bob", 1)
		},
		"uppercase identity with matching name": func(cm *corev1.ConfigMap) {
			cm.Name, _ = UserConfigMapName("Alice")
			cm.Data[UserRecordKey] = strings.Replace(string(data), "username: alice", "username: Alice", 1)
		},
		"wrong configuration": func(cm *corev1.ConfigMap) {
			cm.Data[UserRecordKey] = strings.Replace(string(data), "configurationFingerprint: fingerprint", "configurationFingerprint: other", 1)
		},
		"missing found": func(cm *corev1.ConfigMap) {
			cm.Data[UserRecordKey] = strings.Replace(string(data), "found: true\n", "", 1)
		},
		"unknown field":    func(cm *corev1.ConfigMap) { cm.Data[UserRecordKey] += "unknown: true\n" },
		"duplicate field":  func(cm *corev1.ConfigMap) { cm.Data[UserRecordKey] += "username: bob\n" },
		"unmanaged object": func(cm *corev1.ConfigMap) { delete(cm.Labels, ManagedLabel) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			cm := base.DeepCopy()
			change(cm)
			entry := store.Decode(cm)
			if entry.Invalid == nil || entry.Record != nil {
				t.Fatalf("invalid record published: %+v", entry)
			}
			if entry.Name != cm.Name || entry.ResourceVersion != cm.ResourceVersion {
				t.Fatal("invalid record lost its update preconditions")
			}
		})
	}
}
