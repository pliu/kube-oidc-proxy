// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cliflag "k8s.io/component-base/cli/flag"
)

// LeaderElectionOptions configures mandatory Lease-based leader election.
type LeaderElectionOptions struct {
	LeaseDuration     metav1.Duration
	RenewDeadline     metav1.Duration
	RetryPeriod       metav1.Duration
	ResourceName      string
	ResourceNamespace string
}

func NewLeaderElectionOptions(nfs *cliflag.NamedFlagSets) *LeaderElectionOptions {
	l := &LeaderElectionOptions{
		LeaseDuration: metav1.Duration{Duration: 15 * time.Second},
		RenewDeadline: metav1.Duration{Duration: 10 * time.Second},
		RetryPeriod:   metav1.Duration{Duration: 2 * time.Second},
		ResourceName:  AppName,
	}

	fs := nfs.FlagSet("Leader Election")
	fs.DurationVar(&l.LeaseDuration.Duration, "leader-elect-lease-duration", l.LeaseDuration.Duration, "How long a Lease remains valid without renewal.")
	fs.DurationVar(&l.RenewDeadline.Duration, "leader-elect-renew-deadline", l.RenewDeadline.Duration, "How long the leader retries renewal before giving up leadership.")
	fs.DurationVar(&l.RetryPeriod.Duration, "leader-elect-retry-period", l.RetryPeriod.Duration, "How often replicas attempt to acquire or renew the Lease.")
	fs.StringVar(&l.ResourceName, "leader-elect-resource-name", l.ResourceName, "Name of the leader election Lease.")
	fs.StringVar(&l.ResourceNamespace, "leader-elect-resource-namespace", l.ResourceNamespace, "Namespace of the leader election Lease. Defaults to the namespace the proxy is running in.")

	return l
}

func (l *LeaderElectionOptions) Validate() []error {
	var errs []error

	if l.ResourceName == "" {
		errs = append(errs, errors.New("--leader-elect-resource-name must be set"))
	}

	if l.LeaseDuration.Duration <= l.RenewDeadline.Duration {
		errs = append(errs, errors.New("--leader-elect-lease-duration must be greater than --leader-elect-renew-deadline"))
	}

	if l.RetryPeriod.Duration <= 0 {
		errs = append(errs, errors.New("--leader-elect-retry-period must be greater than zero"))
	}

	return errs
}
