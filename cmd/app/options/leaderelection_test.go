// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"
)

func TestLeaderElectionOptionsValidate(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*LeaderElectionOptions)
		expErrs int
	}{
		"the defaults are valid": {
			mutate: func(*LeaderElectionOptions) {},
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

func TestLeaderElectionCannotBeDisabled(t *testing.T) {
	flags := new(cliflag.NamedFlagSets)
	NewLeaderElectionOptions(flags)
	fs := flags.FlagSet("Leader Election")
	fs.Init("Leader Election", pflag.ContinueOnError)
	if err := fs.Parse([]string{"--leader-elect=false"}); err == nil {
		t.Fatal("expected the removed leader-elect flag to be rejected")
	}
}
