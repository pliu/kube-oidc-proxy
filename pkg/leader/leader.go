// Copyright Jetstack Ltd. See LICENSE for details.
package leader

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
)

// isLeader is 1 on the one replica currently holding the lease, and 0 on every
// other. Summed across replicas it should be 1; 0 for longer than a lease
// duration means nobody is leading, and more than 1 means the lease is not
// doing its job.
var isLeader = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: "kube_oidc_proxy",
	Name:      "is_leader",
	Help:      "1 if this replica holds the leader election lease, and 0 otherwise.",
})

// registerMetrics publishes the metrics once, when the first elector is constructed.
var registerMetrics = sync.OnceFunc(func() {
	prometheus.MustRegister(isLeader)
})

// Config describes the Lease the replicas contend for and how often they do.
type Config struct {
	// Namespace and Name identify the Lease.
	Namespace string
	Name      string

	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

// Elector takes part in electing one replica leader. Every replica keeps
// serving requests whether or not it leads: leading is something to ask
// about, not a precondition for running.
type Elector struct {
	elector    *leaderelection.LeaderElector
	identity   string
	mu         sync.RWMutex
	leadership context.Context
}

// New prepares an Elector. Nothing contends for the Lease until Run.
func New(client kubernetes.Interface, config Config) (*Elector, error) {
	identity, err := newIdentity()
	if err != nil {
		return nil, err
	}

	e := &Elector{identity: identity}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Namespace: config.Namespace,
			Name:      config.Name,
		},
		Client:     client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: identity},
	}

	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          lock,
		Name:          config.Name,
		LeaseDuration: config.LeaseDuration,
		RenewDeadline: config.RenewDeadline,
		RetryPeriod:   config.RetryPeriod,

		// Released on shutdown, so that a rollout hands leadership over as
		// soon as the old leader stops rather than a lease duration later.
		ReleaseOnCancel: true,

		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				if !e.startLeading(ctx) {
					return
				}
				klog.Infof("became leader, holding Lease %s/%s as %q",
					config.Namespace, config.Name, identity)
			},
			OnStoppedLeading: func() {
				// Called on every exit from a round, led or not, so only a
				// replica that was leading has anything to say.
				if e.stopLeading() {
					klog.Infof("stopped leading, no longer holding Lease %s/%s",
						config.Namespace, config.Name)
				}
			},
			OnNewLeader: func(leader string) {
				if leader != identity {
					klog.V(2).Infof("replica %q is leader", leader)
				}
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set up leader election: %s", err)
	}

	e.elector = elector

	registerMetrics()

	return e, nil
}

// Run contends for the Lease until stopCh is closed. It returns at once; the
// channel it returns is closed once the Lease has been released, so that a
// shutdown can wait for leadership to be handed over.
//
// Losing the Lease - a renewal that could not reach the API server in time,
// say - is not fatal. The proxy has other work than leading, so it goes back
// to contending rather than exiting.
func (e *Elector) Run(stopCh <-chan struct{}) <-chan struct{} {
	ctx := wait.ContextForChannel(stopCh)

	done := make(chan struct{})
	go func() {
		defer close(done)

		for {
			e.elector.Run(ctx)

			if ctx.Err() != nil {
				return
			}

			klog.Warning("lost leader election Lease, contending for it again")
		}
	}()

	return done
}

// IsLeader reports whether this replica currently holds the Lease.
func (e *Elector) IsLeader() bool {
	return e.LeadershipContext() != nil
}

// Identity is what this replica records in the Lease when it holds it.
func (e *Elector) Identity() string {
	return e.identity
}

// LeadershipContext returns the current leadership term, or nil for a follower.
// The election library cancels the context as soon as that term ends. Consumers
// should retain it for the duration of their work rather than poll IsLeader.
func (e *Elector) LeadershipContext() context.Context {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.leadership == nil || e.leadership.Err() != nil {
		return nil
	}
	return e.leadership
}

func (e *Elector) startLeading(ctx context.Context) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	// OnStartedLeading is asynchronous; an old callback must not publish a
	// canceled term over a newer one or after shutdown.
	if ctx.Err() != nil {
		return false
	}
	e.leadership = ctx
	isLeader.Set(1)
	return true
}

func (e *Elector) stopLeading() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	led := e.leadership != nil
	e.leadership = nil
	isLeader.Set(0)
	return led
}

// newIdentity names this replica in the Lease. The hostname is the pod name,
// which is what somebody reading the Lease wants to see; the suffix keeps two
// processes that share a hostname from both believing they hold it.
func newIdentity() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to determine an identity for leader election: %s", err)
	}

	return hostname + "_" + string(uuid.NewUUID()), nil
}
