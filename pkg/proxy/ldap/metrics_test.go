// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
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

func TestUserRefreshFailuresAreCounted(t *testing.T) {
	d, _ := userTestDirectory(t)
	realtime := userRefreshFailures.WithLabelValues(triggerRealtime)
	async := userRefreshFailures.WithLabelValues(triggerAsync)

	d.resolver.backends[0].dial = func(string) (conn, error) {
		return connWithUsers([]string{"Admins"}, map[string][]string{"alice": {"Admins"}}), nil
	}
	if _, err := d.Resolve(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}

	d.resolver.backends[0].dial = func(string) (conn, error) {
		return nil, errors.New("directory unavailable")
	}

	before := testutil.ToFloat64(realtime)
	if _, err := d.Resolve(context.Background(), "bob"); err == nil {
		t.Fatal("expected the lookup of an uncached user to fail")
	}
	if got := testutil.ToFloat64(realtime) - before; got != 1 {
		t.Errorf("expected one realtime failure, got %v", got)
	}

	before = testutil.ToFloat64(async)
	if err := d.RefreshCached(context.Background()); err == nil {
		t.Fatal("expected the refresh to fail")
	}
	if got := testutil.ToFloat64(async) - before; got != 1 {
		t.Errorf("expected one async failure, got %v", got)
	}
}
