// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"testing"
	"time"

	cliflag "k8s.io/component-base/cli/flag"
)

func TestLeaderElectionOptionsValidate(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*LeaderElectionOptions)
		expErrs int
	}{
		"disabled is never an error": {
			mutate: func(l *LeaderElectionOptions) {
				l.LeaderElect = false
				l.ResourceName = ""
			},
		},
		"the defaults are valid": {
			mutate: func(*LeaderElectionOptions) {},
		},
		"a lock other than leases": {
			mutate:  func(l *LeaderElectionOptions) { l.ResourceLock = "endpoints" },
			expErrs: 1,
		},
		"no lease name": {
			mutate:  func(l *LeaderElectionOptions) { l.ResourceName = "" },
			expErrs: 1,
		},
		"a renew deadline no shorter than the lease": {
			mutate:  func(l *LeaderElectionOptions) { l.RenewDeadline.Duration = l.LeaseDuration.Duration },
			expErrs: 1,
		},
		"no retry period": {
			mutate:  func(l *LeaderElectionOptions) { l.RetryPeriod.Duration = 0 * time.Second },
			expErrs: 1,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			l := NewLeaderElectionOptions(new(cliflag.NamedFlagSets))
			test.mutate(l)

			if errs := l.Validate(); len(errs) != test.expErrs {
				t.Errorf("expected %d errors, got %v", test.expErrs, errs)
			}
		})
	}
}
