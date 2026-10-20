// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	k8sErrors "k8s.io/apimachinery/pkg/util/errors"

	cliflag "k8s.io/component-base/cli/flag"
)

const (
	AppName = "kube-oidc-proxy"
)

type Options struct {
	App                *KubeOIDCProxyOptions
	OIDCAuthentication *OIDCAuthenticationOptions
	SecureServing      *SecureServingOptions
	Audit              *AuditOptions
	Client             *ClientOptions
	Misc               *MiscOptions
	LDAP               *LDAPOptions
	LeaderElection     *LeaderElectionOptions

	nfs *cliflag.NamedFlagSets
}

func New() *Options {
	nfs := new(cliflag.NamedFlagSets)

	// Add flags to command sets
	return &Options{
		App:                NewKubeOIDCProxyOptions(nfs),
		OIDCAuthentication: NewOIDCAuthenticationOptions(nfs),
		SecureServing:      NewSecureServingOptions(nfs),
		Audit:              NewAuditOptions(nfs),
		Client:             NewClientOptions(nfs),
		Misc:               NewMiscOptions(nfs),
		LDAP:               NewLDAPOptions(nfs),
		LeaderElection:     NewLeaderElectionOptions(nfs),

		nfs: nfs,
	}
}

func (o *Options) AddFlags(cmd *cobra.Command) {
	// pretty output from kube-apiserver
	usageFmt := "Usage:\n  %s\n"
	cols, _, _ := term.GetSize(0)
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), *o.nfs, cols)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), *o.nfs, cols)
	})

	fs := cmd.Flags()
	for _, f := range o.nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

func (o *Options) Validate(cmd *cobra.Command) error {
	if cmd.Flag("version").Value.String() == "true" {
		o.Misc.PrintVersionAndExit()
	}

	var errs []error

	// Passthrough leaves authentication to the API server, so it needs no
	// issuers. A file given anyway is ignored rather than refused: it changes
	// nothing about what a request may do.
	if !o.App.TokenPassthrough.Enabled {
		if err := o.OIDCAuthentication.Validate(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := o.SecureServing.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if o.SecureServing.BindPort == o.App.ReadinessProbePort {
		errs = append(errs, fmt.Errorf("unable to securely serve on port %d (used by readiness probe)", o.App.ReadinessProbePort))
	}

	if err := o.Audit.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if err := o.LDAP.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if err := o.LeaderElection.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if o.LDAP.Enabled() {
		if _, err := o.OIDCAuthentication.SharedUsernamePrefix(); err != nil {
			errs = append(errs, err)
		}
	}

	// Passthrough forwards requests as they are, so neither the groups of the
	// directory nor extra user headers would ever reach the API server.
	// Refused, so that a configuration asking for them is not quietly served
	// without them.
	if o.App.TokenPassthrough.Enabled && o.LDAP.Enabled() {
		errs = append(errs, errors.New("--token-passthrough cannot be used with --ldap-config-file"))
	}

	if o.App.TokenPassthrough.Enabled &&
		(o.App.ExtraHeaderOptions.EnableClientIPExtraUserHeader || len(o.App.ExtraHeaderOptions.ExtraUserHeaders) > 0) {
		errs = append(errs, errors.New("--token-passthrough cannot be used with extra user headers"))
	}

	if len(errs) > 0 {
		return k8sErrors.NewAggregate(errs)
	}

	return nil
}
