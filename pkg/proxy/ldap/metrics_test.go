// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func sampleCount(t *testing.T, o prometheus.Observer) uint64 {
	t.Helper()
	var m dto.Metric
	if err := o.(prometheus.Metric).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestRefreshDurationMetrics(t *testing.T) {
	d, _ := userTestDirectory(t)
	d.resolver.backends[0].dial = func(string) (conn, error) {
		return connWithUsers([]string{"Admins"}, map[string][]string{"alice": {"Admins"}}), nil
	}

	backend := d.resolver.backends[0].config.Name
	realtime := backendRefreshDuration.WithLabelValues(backend, triggerRealtime)
	async := backendRefreshDuration.WithLabelValues(backend, triggerAsync)
	counts := func() [3]uint64 {
		return [3]uint64{sampleCount(t, realtime), sampleCount(t, async), sampleCount(t, fullRefreshDuration)}
	}
	expectDelta := func(step string, before [3]uint64, want [3]uint64) {
		t.Helper()
		after := counts()
		for i, name := range []string{"realtime", "async", "full"} {
			if got := after[i] - before[i]; got != want[i] {
				t.Errorf("%s: %s observations = %d, want %d", step, name, got, want[i])
			}
		}
	}

	before := counts()
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	expectDelta("first request", before, [3]uint64{1, 0, 0})

	before = counts()
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	expectDelta("cached request", before, [3]uint64{0, 0, 0})

	before = counts()
	if err := d.RefreshCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectDelta("full refresh", before, [3]uint64{0, 1, 1})

	// A cycle cut short did not do a full refresh.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before = counts()
	if err := d.RefreshCached(ctx); err == nil {
		t.Fatal("expected a canceled cycle to fail")
	}
	expectDelta("canceled refresh", before, [3]uint64{0, 0, 0})
}

func TestUserRefreshFailuresAreCountedBySource(t *testing.T) {
	d, client := userTestDirectory(t)
	ldapFailures := userRefreshFailures.WithLabelValues(failureLDAP)
	kubeFailures := userRefreshFailures.WithLabelValues(failureKubernetes)
	expectDelta := func(step string, ldapBefore, kubeBefore, wantLDAP, wantKube float64) {
		t.Helper()
		if got := testutil.ToFloat64(ldapFailures) - ldapBefore; got != wantLDAP {
			t.Errorf("%s: ldap failures = %v, want %v", step, got, wantLDAP)
		}
		if got := testutil.ToFloat64(kubeFailures) - kubeBefore; got != wantKube {
			t.Errorf("%s: kubernetes failures = %v, want %v", step, got, wantKube)
		}
	}

	d.resolver.backends[0].dial = func(string) (conn, error) {
		return connWithUsers([]string{"Admins"}, map[string][]string{"alice": {"Admins"}, "carol": {"Admins"}}), nil
	}
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}

	// The cache ConfigMap cannot be written.
	client.PrependReactor("create", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("API unavailable")
	})
	ldapBefore, kubeBefore := testutil.ToFloat64(ldapFailures), testutil.ToFloat64(kubeFailures)
	if _, err := d.Resolve(context.Background(), "carol"); err == nil {
		t.Fatal("expected an unpersisted lookup to fail")
	}
	expectDelta("ConfigMap write", ldapBefore, kubeBefore, 0, 1)

	// The directory cannot be reached, by a request or by the refresh cycle.
	d.resolver.backends[0].dial = func(string) (conn, error) {
		return nil, errors.New("directory unavailable")
	}
	ldapBefore, kubeBefore = testutil.ToFloat64(ldapFailures), testutil.ToFloat64(kubeFailures)
	if _, err := d.Resolve(context.Background(), "bob"); err == nil {
		t.Fatal("expected the lookup of an uncached user to fail")
	}
	if err := d.RefreshCached(context.Background()); err == nil {
		t.Fatal("expected the refresh to fail")
	}
	expectDelta("directory", ldapBefore, kubeBefore, 2, 0)
}
