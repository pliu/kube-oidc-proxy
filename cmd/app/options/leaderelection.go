// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"errors"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cliflag "k8s.io/component-base/cli/flag"
	componentbaseconfig "k8s.io/component-base/config"
	componentbaseoptions "k8s.io/component-base/config/options"
)

// LeaderElectionOptions configures electing one replica leader. The flags are
// the standard --leader-elect set that Kubernetes components use, except that
// election is on by default: --leader-elect=false is for running the proxy
// outside a cluster, where there is no namespace to hold the Lease in.
type LeaderElectionOptions struct {
	componentbaseconfig.LeaderElectionConfiguration
}

func NewLeaderElectionOptions(nfs *cliflag.NamedFlagSets) *LeaderElectionOptions {
	l := &LeaderElectionOptions{
		LeaderElectionConfiguration: componentbaseconfig.LeaderElectionConfiguration{
			LeaderElect:   true,
			LeaseDuration: metav1.Duration{Duration: 15 * time.Second},
			RenewDeadline: metav1.Duration{Duration: 10 * time.Second},
			RetryPeriod:   metav1.Duration{Duration: 2 * time.Second},
			ResourceLock:  "leases",
			ResourceName:  AppName,
		},
	}

	fs := nfs.FlagSet("Leader Election")
	componentbaseoptions.BindLeaderElectionFlags(&l.LeaderElectionConfiguration, fs)

	// Left out of the help: leases are the only lock supported, and the flag
	// exists only because it is part of the standard set.
	_ = fs.MarkHidden("leader-elect-resource-lock")

	fs.Lookup("leader-elect").Usage = "Elect one replica leader through a Lease. Every " +
		"replica serves requests whether or not it leads. Set to false to run the proxy " +
		"outside a cluster."

	fs.Lookup("leader-elect-resource-namespace").Usage += " Defaults to the namespace the proxy is running in."

	return l
}

func (l *LeaderElectionOptions) Validate() []error {
	if !l.LeaderElect {
		return nil
	}

	var errs []error

	if l.ResourceLock != "leases" {
		errs = append(errs, fmt.Errorf("--leader-elect-resource-lock must be %q, got %q",
			"leases", l.ResourceLock))
	}

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
