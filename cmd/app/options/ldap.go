// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap"
)

// LDAPOptions points at the file holding the LDAP configuration.
// The configuration itself is a JSON document rather than a set of flags,
// since it describes a list of backends and how the mapping they are merged
// into is persisted, neither of which a flat flag set expresses well.
type LDAPOptions struct {
	ConfigFile string

	// config is the parsed contents of ConfigFile, populated by Validate so
	// that a bad configuration file is reported before anything is started.
	config *ldap.Config
}

func NewLDAPOptions(nfs *cliflag.NamedFlagSets) *LDAPOptions {
	return new(LDAPOptions).AddFlags(nfs.FlagSet("LDAP"))
}

func (l *LDAPOptions) AddFlags(fs *pflag.FlagSet) *LDAPOptions {
	fs.StringVar(&l.ConfigFile, "ldap-config-file", l.ConfigFile,
		"(Alpha) Path to the JSON file configuring the LDAP backends that "+
			"authenticated requests are augmented with groups from. When set, the user "+
			"name is still taken from the token but the groups are taken from the "+
			"directories. The file is checked against a schema, which is documented in "+
			"docs/tasks/ldap-group-augmentation.md.")

	return l
}

// Enabled reports whether LDAP group augmentation is configured.
func (l *LDAPOptions) Enabled() bool {
	return l.ConfigFile != ""
}

func (l *LDAPOptions) Validate() []error {
	if !l.Enabled() {
		return nil
	}

	config, err := ldap.LoadConfig(l.ConfigFile)
	if err != nil {
		return []error{err}
	}

	l.config = config

	return nil
}

// Config returns the loaded configuration with the OIDC username prefix
// threaded in, loading it first if Validate has not already done so.
func (l *LDAPOptions) Config(usernamePrefix string) (*ldap.Config, error) {
	if l.config == nil {
		config, err := ldap.LoadConfig(l.ConfigFile)
		if err != nil {
			return nil, err
		}

		l.config = config
	}

	l.config.UsernamePrefix = usernamePrefix

	return l.config, nil
}
