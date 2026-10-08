// Copyright Jetstack Ltd. See LICENSE for details.
package leader

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func testConfig() Config {
	return Config{
		Namespace:     "kube-oidc-proxy",
		Name:          "kube-oidc-proxy",
		LeaseDuration: time.Second * 2,
		RenewDeadline: time.Second,
		RetryPeriod:   time.Millisecond * 100,
	}
}

func newTestElector(t *testing.T, client kubernetes.Interface) *Elector {
	t.Helper()

	e, err := New(client, testConfig())
	if err != nil {
		t.Fatalf("unexpected error building elector: %s", err)
	}

	return e
}

// waitFor polls until condition holds, failing the test if it never does.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(time.Second * 10)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond * 20)
	}
}

func leaders(electors ...*Elector) int {
	var n int
	for _, e := range electors {
		if e.IsLeader() {
			n++
		}
	}
	return n
}

// Of any number of replicas contending for one Lease, exactly one leads.
func TestOnlyOneReplicaLeads(t *testing.T) {
	client := fake.NewSimpleClientset()

	electors := []*Elector{
		newTestElector(t, client),
		newTestElector(t, client),
		newTestElector(t, client),
	}

	stopCh := make(chan struct{})
	var done []<-chan struct{}
	for _, e := range electors {
		done = append(done, e.Run(stopCh))
	}
	defer func() {
		close(stopCh)
		for _, d := range done {
			<-d
		}
	}()

	waitFor(t, "a leader to be elected", func() bool { return leaders(electors...) == 1 })

	// And it stays that way over several renewals, rather than being true
	// only for a moment.
	for range 20 {
		if n := leaders(electors...); n != 1 {
			t.Fatalf("expected exactly one leader, got %d", n)
		}
		time.Sleep(time.Millisecond * 50)
	}

	lease, err := client.CoordinationV1().Leases("kube-oidc-proxy").
		Get(context.Background(), "kube-oidc-proxy", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error getting the Lease: %s", err)
	}

	var holder *Elector
	for _, e := range electors {
		if e.IsLeader() {
			holder = e
		}
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != holder.Identity() {
		t.Errorf("expected the Lease to be held by the leader %q, got %v",
			holder.Identity(), lease.Spec.HolderIdentity)
	}
}

// A leader that shuts down releases the Lease, so another replica takes over
// without waiting for the Lease to expire.
func TestLeadershipIsHandedOverOnShutdown(t *testing.T) {
	client := fake.NewSimpleClientset()

	first := newTestElector(t, client)
	firstStop := make(chan struct{})
	firstDone := first.Run(firstStop)

	waitFor(t, "the first replica to lead", first.IsLeader)
	term := first.LeadershipContext()
	if term == nil {
		t.Fatal("leader did not expose its term")
	}

	second := newTestElector(t, client)
	secondStop := make(chan struct{})
	secondDone := second.Run(secondStop)
	defer func() {
		close(secondStop)
		<-secondDone
	}()

	// Give the second replica a chance to (wrongly) take the Lease.
	time.Sleep(time.Millisecond * 300)
	if second.IsLeader() {
		t.Fatal("expected the second replica not to lead while the first holds the Lease")
	}

	close(firstStop)
	<-firstDone

	if first.IsLeader() {
		t.Error("expected a replica that has shut down not to report itself leader")
	}
	select {
	case <-term.Done():
	default:
		t.Error("shutdown did not cancel the leadership term")
	}

	waitFor(t, "the second replica to take over", second.IsLeader)
}

func TestCanceledTermCannotReplaceLiveLeadership(t *testing.T) {
	e := newTestElector(t, fake.NewClientset())
	stale, cancelStale := context.WithCancel(context.Background())
	cancelStale()
	if e.startLeading(stale) || e.IsLeader() {
		t.Fatal("published an already-ended term")
	}
	live, cancelLive := context.WithCancel(context.Background())
	defer cancelLive()
	if !e.startLeading(live) {
		t.Fatal("rejected live term")
	}
	if e.startLeading(stale) || e.LeadershipContext() != live {
		t.Fatal("late callback replaced live leadership")
	}
	cancelLive()
	if e.LeadershipContext() != nil || e.IsLeader() {
		t.Fatal("canceled term still reports leadership")
	}
	e.stopLeading()
}
