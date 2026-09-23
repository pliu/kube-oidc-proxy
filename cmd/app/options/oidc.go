// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/apis/apiserver/install"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	cliflag "k8s.io/component-base/cli/flag"
	"sigs.k8s.io/yaml"
)

var configScheme = runtime.NewScheme()

func init() {
	install.Install(configScheme)
}

// defaultSigningAlgs is what an issuer that names none is held to. RS256 is
// the algorithm every OpenID Connect provider is required to implement.
var defaultSigningAlgs = []string{"RS256"}

// Issuer is one issuer the proxy trusts.
type Issuer struct {
	JWTAuthenticator apiserver.JWTAuthenticator

	// SigningAlgs are the JOSE algorithms its tokens may be signed with.
	SigningAlgs []string
}

type OIDCAuthenticationOptions struct {
	ConfigFile string

	issuers []Issuer
}

func NewOIDCAuthenticationOptions(nfs *cliflag.NamedFlagSets) *OIDCAuthenticationOptions {
	return new(OIDCAuthenticationOptions).AddFlags(nfs.FlagSet("OIDC"))
}

func (o *OIDCAuthenticationOptions) Validate() error {
	if o == nil {
		return nil
	}

	if len(o.ConfigFile) == 0 {
		return errors.New("--oidc-config-file is required")
	}

	_, err := o.Issuers()
	return err
}

// Issuers returns the issuers to trust, as listed in the configuration file.
func (o *OIDCAuthenticationOptions) Issuers() ([]Issuer, error) {
	if o.issuers != nil {
		return o.issuers, nil
	}

	issuers, err := loadIssuers(o.ConfigFile)
	if err != nil {
		return nil, err
	}

	o.issuers = issuers

	return issuers, nil
}

// SharedUsernamePrefix returns the username prefix every trusted issuer puts
// on its usernames. LDAP entries are keyed on raw usernames, so the proxy can
// only look a user up in them when it knows which prefix to take off - with
// issuers that prefix differently, users of different issuers who share a raw
// username would be handed each other's directory groups.
func (o *OIDCAuthenticationOptions) SharedUsernamePrefix() (string, error) {
	issuers, err := o.Issuers()
	if err != nil {
		return "", err
	}

	var prefix string
	for i, issuer := range issuers {
		var p string
		if issuer.JWTAuthenticator.ClaimMappings.Username.Prefix != nil {
			p = *issuer.JWTAuthenticator.ClaimMappings.Username.Prefix
		}

		if i > 0 && p != prefix {
			return "", fmt.Errorf("LDAP group augmentation requires every issuer to use the same "+
				"username prefix, got %q and %q", prefix, p)
		}

		prefix = p
	}

	return prefix, nil
}

// configFile is the file --oidc-config-file names.
type configFile struct {
	Issuers []configIssuer `json:"issuers"`
}

// configIssuer is a jwt entry of kube-apiserver's AuthenticationConfiguration
// with the algorithms its tokens may be signed with, which kube-apiserver
// takes from a flag instead.
type configIssuer struct {
	apiserverv1.JWTAuthenticator `json:",inline"`

	SigningAlgs []string `json:"signingAlgs,omitempty"`
}

// loadIssuers reads the issuers out of the file --oidc-config-file names.
func loadIssuers(path string) ([]Issuer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read --oidc-config-file: %w", err)
	}

	// A kube-apiserver --authentication-config file is the likeliest thing to
	// be handed here by mistake, and its first unknown field says little.
	var fields map[string]interface{}
	if err := yaml.Unmarshal(data, &fields); err == nil {
		if _, ok := fields["jwt"]; ok {
			return nil, errors.New("--oidc-config-file: found jwt, the issuers of a kube-apiserver " +
				"AuthenticationConfiguration; list them under issuers instead, without apiVersion and kind")
		}
	}

	var file configFile
	if err := yaml.UnmarshalStrict(data, &file); err != nil {
		return nil, fmt.Errorf("failed to decode --oidc-config-file: %w", err)
	}

	if len(file.Issuers) == 0 {
		return nil, errors.New("--oidc-config-file: at least one issuer is required")
	}

	// Validated as kube-apiserver would an AuthenticationConfiguration of the
	// same issuers, so every rule it holds its issuers to holds here too.
	external := &apiserverv1.AuthenticationConfiguration{}
	for _, issuer := range file.Issuers {
		external.JWT = append(external.JWT, issuer.JWTAuthenticator)
	}

	configScheme.Default(external)

	config := &apiserver.AuthenticationConfiguration{}
	if err := configScheme.Convert(external, config, nil); err != nil {
		return nil, fmt.Errorf("--oidc-config-file: %w", err)
	}

	errs := validation.ValidateAuthenticationConfiguration(authenticationcel.NewDefaultCompiler(), config, nil)
	for _, err := range errs {
		// The issuers are under jwt in an AuthenticationConfiguration, and
		// under issuers in this file.
		if strings.HasPrefix(err.Field, "jwt") {
			err.Field = "issuers" + strings.TrimPrefix(err.Field, "jwt")
		}
	}
	if err := errs.ToAggregate(); err != nil {
		return nil, fmt.Errorf("--oidc-config-file: %w", err)
	}

	valid := sets.New(oidc.AllValidSigningAlgorithms()...)

	issuers := make([]Issuer, 0, len(config.JWT))
	for i, jwtAuthenticator := range config.JWT {
		algs := file.Issuers[i].SigningAlgs
		if algs == nil {
			algs = defaultSigningAlgs
		}

		if len(algs) == 0 {
			return nil, fmt.Errorf("--oidc-config-file: issuers[%d].signingAlgs must not be empty", i)
		}

		for _, alg := range algs {
			if !valid.Has(alg) {
				return nil, fmt.Errorf("--oidc-config-file: issuers[%d].signingAlgs: unsupported signing algorithm %q, must be one of %v",
					i, alg, sets.List(valid))
			}
		}

		issuers = append(issuers, Issuer{
			JWTAuthenticator: jwtAuthenticator,
			SigningAlgs:      algs,
		})
	}

	return issuers, nil
}

func (o *OIDCAuthenticationOptions) AddFlags(fs *pflag.FlagSet) *OIDCAuthenticationOptions {
	fs.StringVar(&o.ConfigFile, "oidc-config-file", o.ConfigFile, ""+
		"Path to a YAML file listing every issuer to trust under issuers. Each issuer takes the "+
		"fields of a jwt entry of kube-apiserver's --authentication-config, and signingAlgs, the "+
		"JOSE algorithms its tokens may be signed with (default [RS256]).")

	return o
}
