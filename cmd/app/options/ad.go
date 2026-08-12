// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ad"
)

// ADOptions points at the file holding the Active Directory configuration.
// The configuration itself is a JSON document rather than a set of flags,
// since it describes a list of backends and how the mapping they are merged
// into is persisted, neither of which a flat flag set expresses well.
type ADOptions struct {
	ConfigFile string

	// config is the parsed contents of ConfigFile, populated by Validate so
	// that a bad configuration file is reported before anything is started.
	config *ad.Config
}

func NewADOptions(nfs *cliflag.NamedFlagSets) *ADOptions {
	return new(ADOptions).AddFlags(nfs.FlagSet("Active Directory"))
}

func (a *ADOptions) AddFlags(fs *pflag.FlagSet) *ADOptions {
	fs.StringVar(&a.ConfigFile, "ad-config-file", a.ConfigFile,
		"(Alpha) Path to the JSON file configuring the Active Directory backends that "+
			"authenticated requests are augmented with groups from. When set, the user "+
			"name is still taken from the token but the groups are taken from the "+
			"directories. The file is checked against a schema, which is documented in "+
			"docs/tasks/ad-group-augmentation.md.")

	return a
}

// Enabled reports whether Active Directory group augmentation is configured.
func (a *ADOptions) Enabled() bool {
	return a.ConfigFile != ""
}

func (a *ADOptions) Validate() []error {
	if !a.Enabled() {
		return nil
	}

	config, err := ad.LoadConfig(a.ConfigFile)
	if err != nil {
		return []error{err}
	}

	a.config = config

	return nil
}

// Config returns the loaded configuration with the OIDC username prefix
// threaded in, loading it first if Validate has not already done so.
func (a *ADOptions) Config(usernamePrefix string) (*ad.Config, error) {
	if a.config == nil {
		config, err := ad.LoadConfig(a.ConfigFile)
		if err != nil {
			return nil, err
		}

		a.config = config
	}

	a.config.UsernamePrefix = usernamePrefix

	return a.config, nil
}
