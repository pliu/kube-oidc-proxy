// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestPersistenceFailureDoesNotPublish(t *testing.T) {
	d, client := userTestDirectory(t)
	d.resolver.backends[0].dial = func(string) (conn, error) {
		return connWithUsers([]string{"Admins"}, map[string][]string{"alice": {"Admins"}}), nil
	}
	client.PrependReactor("create", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("API unavailable") })
	if _, err := d.Resolve(context.Background(), "alice"); err == nil {
		t.Fatal("unpersisted result served")
	}
	if _, ok := d.cached("alice"); ok {
		t.Fatal("unpersisted result published")
	}
}

func TestConflictDiscardsLookupAndReloadsWinner(t *testing.T) {
	d, client := userTestDirectory(t)
	winner := userTestEntry(t, d, "200", "Winner")
	data, _ := cache.EncodeUserRecord(winner.Record)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: winner.Name, Namespace: "proxy", ResourceVersion: "200", Labels: map[string]string{cache.ManagedLabel: "kube-oidc-proxy"}}, Data: map[string]string{cache.UserRecordKey: string(data)}}
	d.resolver.backends[0].dial = func(string) (conn, error) {
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, "proxy"); err != nil {
			t.Error(err)
		}
		return connWithUsers([]string{"Stale"}, map[string][]string{"alice": {"Stale"}}), nil
	}
	groups, err := d.Resolve(context.Background(), "alice")
	if err != nil || len(groups) != 1 || groups[0] != "Winner" {
		t.Fatalf("stale lookup won: %v %v", groups, err)
	}
}

func TestRefreshFailureKeepsOldAndOtherUsersAdvance(t *testing.T) {
	d, client := userTestDirectory(t)
	d.resolver.backends[0].dial = func(string) (conn, error) {
		return connWithUsers([]string{"Old"}, map[string][]string{"alice": {"Old"}, "bob": {"Old"}}), nil
	}
	for _, key := range []string{"alice", "bob"} {
		if _, err := d.Resolve(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	alice, _ := d.cached("alice")
	client.PrependReactor("update", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.(ktesting.UpdateAction).GetObject().(*corev1.ConfigMap).Name == alice.Name {
			return true, nil, errors.New("write failed")
		}
		return false, nil, nil
	})
	d.resolver.backends[0].dial = func(string) (conn, error) {
		return connWithUsers([]string{"New"}, map[string][]string{"alice": {"New"}, "bob": {"New"}}), nil
	}
	if err := d.RefreshCached(context.Background()); err == nil {
		t.Fatal("failure not reported")
	}
	alice, _ = d.cached("alice")
	bob, _ := d.cached("bob")
	if alice.Record.Groups[0] != "Old" || bob.Record.Groups[0] != "New" {
		t.Fatalf("alice=%v bob=%v", alice.Record.Groups, bob.Record.Groups)
	}
}

func TestInvalidRecordCanBeRepairedAndUnmanagedRecordCannot(t *testing.T) {
	for _, managed := range []bool{true, false} {
		t.Run(map[bool]string{true: "managed", false: "unmanaged"}[managed], func(t *testing.T) {
			d, client := userTestDirectory(t)
			name, _ := cache.UserConfigMapName("alice")
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "proxy"}, Data: map[string]string{cache.UserRecordKey: "broken: ["}}
			if managed {
				cm.Labels = map[string]string{cache.ManagedLabel: "kube-oidc-proxy"}
			}
			if _, err := client.CoreV1().ConfigMaps("proxy").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			d.resolver.backends[0].dial = func(string) (conn, error) { return connWithUsers(nil, nil), nil }
			groups, err := d.Resolve(context.Background(), "alice")
			if managed && (err != nil || len(groups) != 0) {
				t.Fatalf("repair failed: %v %v", groups, err)
			}
			if !managed && err == nil {
				t.Fatal("unmanaged ConfigMap overwritten")
			}
		})
	}
}

func TestUnchangedRefreshAvoidsWrite(t *testing.T) {
	d, client := userTestDirectory(t)
	d.resolver.backends[0].dial = func(string) (conn, error) { return connWithUsers(nil, nil), nil }
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	count := len(client.Actions())
	if _, err := d.resolve(context.Background(), "alice", true); err != nil {
		t.Fatal(err)
	}
	if len(client.Actions()) != count+1 {
		t.Fatal("unchanged record was written")
	}
}

func TestCanceledDialReturnsPromptly(t *testing.T) {
	d, _ := userTestDirectory(t)
	release := make(chan struct{})
	defer close(release)
	d.resolver.backends[0].dial = func(string) (conn, error) { <-release; return nil, errors.New("closed") }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.resolver.searchUser(ctx, "alice", false); err == nil {
		t.Fatal("canceled lookup succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation did not bound dial")
	}
}

// Keep explicit update-conflict coverage separate from create conflicts.
func TestUpdateConflictIsNotRetried(t *testing.T) {
	d, client := userTestDirectory(t)
	d.resolver.backends[0].dial = func(string) (conn, error) { return connWithUsers(nil, nil), nil }
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	client.PrependReactor("update", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		attempts++
		return true, nil, apierrors.NewConflict(corev1.Resource("configmaps"), "alice", errors.New("changed"))
	})
	d.resolver.backends[0].dial = func(string) (conn, error) {
		return connWithUsers([]string{"New"}, map[string][]string{"alice": {"New"}}), nil
	}
	result, err := d.resolve(context.Background(), "alice", true)
	if err != nil || attempts != 1 || len(result.Record.Groups) != 0 {
		t.Fatalf("%+v %v attempts=%d", result, err, attempts)
	}
}
