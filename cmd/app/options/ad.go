// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ad"
)

type ADOptions struct {
	Enabled bool

	URLs                  []string
	BindDN                string
	BindPassword          string
	BindPasswordFile      string
	CAFile                string
	InsecureSkipTLSVerify bool
	StartTLS              bool

	UserSearchBases   []string
	UserFilter        string
	UsernameAttribute string

	GroupSearchBases   []string
	GroupFilter        string
	GroupNameAttribute string
	GroupPrefix        string

	RefreshInterval       time.Duration
	FallbackToTokenGroups bool
}

func NewADOptions(nfs *cliflag.NamedFlagSets) *ADOptions {
	return new(ADOptions).AddFlags(nfs.FlagSet("Active Directory"))
}

func (a *ADOptions) AddFlags(fs *pflag.FlagSet) *ADOptions {
	fs.BoolVar(&a.Enabled, "ad-enabled", a.Enabled,
		"(Alpha) Augment authenticated requests with groups pulled from an Active "+
			"Directory backend. When enabled, the user name is still taken from the "+
			"token but the groups are taken from the directory.")

	fs.StringSliceVar(&a.URLs, "ad-url", a.URLs,
		"URL(s) of the Active Directory server to pull from, e.g. "+
			"'ldaps://ad.example.net:636'. Servers are tried in order until one "+
			"can be connected to and bound.")

	fs.StringVar(&a.BindDN, "ad-bind-dn", a.BindDN,
		"DN to bind to the directory as. If empty, an anonymous bind is used.")

	fs.StringVar(&a.BindPassword, "ad-bind-password", a.BindPassword,
		"Password to bind to the directory with. Prefer --ad-bind-password-file "+
			"to keep the password out of the process arguments.")

	fs.StringVar(&a.BindPasswordFile, "ad-bind-password-file", a.BindPasswordFile,
		"File containing the password to bind to the directory with. Takes "+
			"precedence over --ad-bind-password.")

	fs.StringVar(&a.CAFile, "ad-ca-file", a.CAFile,
		"PEM encoded certificate authority bundle used to verify the directory's "+
			"serving certificate. Defaults to the host's trust store.")

	fs.BoolVar(&a.InsecureSkipTLSVerify, "ad-insecure-skip-tls-verify", a.InsecureSkipTLSVerify,
		"Do not verify the directory's serving certificate. This is insecure and "+
			"should only be used for testing.")

	fs.BoolVar(&a.StartTLS, "ad-start-tls", a.StartTLS,
		"Issue a StartTLS request after connecting. Used with an 'ldap://' URL to "+
			"upgrade the connection to TLS.")

	fs.StringSliceVar(&a.UserSearchBases, "ad-user-search-base", a.UserSearchBases,
		"Base DN(s) to search for users under, e.g. 'OU=Users,DC=example,DC=net'.")

	fs.StringVar(&a.UserFilter, "ad-user-filter", "(objectClass=user)",
		"LDAP filter used to select user entries.")

	fs.StringVar(&a.UsernameAttribute, "ad-username-attribute", "userPrincipalName",
		"Attribute of a user entry that holds the name matching the username of "+
			"the token. Matched case insensitively.")

	fs.StringSliceVar(&a.GroupSearchBases, "ad-group-search-base", a.GroupSearchBases,
		"Base DN(s) to search for groups under, e.g. 'OU=Groups,DC=example,DC=net'. "+
			"Only groups found under these bases are mapped onto users; a user's "+
			"membership of any other group is ignored.")

	fs.StringVar(&a.GroupFilter, "ad-group-filter", "(objectClass=group)",
		"LDAP filter used to select group entries.")

	fs.StringVar(&a.GroupNameAttribute, "ad-group-name-attribute", "cn",
		"Attribute of a group entry to use as the group name.")

	fs.StringVar(&a.GroupPrefix, "ad-group-prefix", a.GroupPrefix,
		"Prefix prepended to every group name pulled from the directory. Note "+
			"that --oidc-groups-prefix is not applied to directory groups.")

	fs.DurationVar(&a.RefreshInterval, "ad-refresh-interval", time.Minute*10,
		"How often the user to group mapping is rebuilt from the directory.")

	fs.BoolVar(&a.FallbackToTokenGroups, "ad-fallback-to-token-groups", a.FallbackToTokenGroups,
		"If a user of a request cannot be found in the directory, fall back to the "+
			"groups in their token. By default such a user is given no groups.")

	return a
}

func (a *ADOptions) Validate() []error {
	if !a.Enabled {
		return nil
	}

	var errs []error

	if len(a.URLs) == 0 {
		errs = append(errs, errors.New("--ad-url must be set when --ad-enabled is set"))
	}

	if len(a.UserSearchBases) == 0 {
		errs = append(errs, errors.New("--ad-user-search-base must be set when --ad-enabled is set"))
	}

	if len(a.GroupSearchBases) == 0 {
		errs = append(errs, errors.New("--ad-group-search-base must be set when --ad-enabled is set"))
	}

	if a.RefreshInterval <= 0 {
		errs = append(errs, errors.New("--ad-refresh-interval must be a positive duration"))
	}

	if a.CAFile != "" && a.InsecureSkipTLSVerify {
		errs = append(errs, errors.New("cannot set both --ad-ca-file and --ad-insecure-skip-tls-verify"))
	}

	return errs
}

// Config builds the directory configuration, resolving the bind password from
// disk if a file was given.
func (a *ADOptions) Config(usernamePrefix string) (*ad.Config, error) {
	bindPassword := a.BindPassword

	if a.BindPasswordFile != "" {
		b, err := os.ReadFile(a.BindPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read --ad-bind-password-file %q: %s",
				a.BindPasswordFile, err)
		}

		bindPassword = strings.TrimRight(string(b), "\r\n")
	}

	return &ad.Config{
		URLs:                  a.URLs,
		BindDN:                a.BindDN,
		BindPassword:          bindPassword,
		CAFile:                a.CAFile,
		InsecureSkipTLSVerify: a.InsecureSkipTLSVerify,
		StartTLS:              a.StartTLS,

		UserSearchBases:   a.UserSearchBases,
		UserFilter:        a.UserFilter,
		UsernameAttribute: a.UsernameAttribute,

		GroupSearchBases:   a.GroupSearchBases,
		GroupFilter:        a.GroupFilter,
		GroupNameAttribute: a.GroupNameAttribute,
		GroupPrefix:        a.GroupPrefix,

		RefreshInterval:       a.RefreshInterval,
		FallbackToTokenGroups: a.FallbackToTokenGroups,

		UsernamePrefix: usernamePrefix,
	}, nil
}
