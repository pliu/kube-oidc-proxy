package cache

import (
	"context"
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
	store, err := NewConfigMaps(client, "proxy", "main", "fingerprint")
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
