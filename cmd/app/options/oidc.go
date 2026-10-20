// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

	// PublicKeys, when set, are the keys its tokens are verified with, in
	// place of the ones its discovery document points to.
	PublicKeys []crypto.PublicKey
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
// takes from a flag instead, and optionally the keys to verify them with.
type configIssuer struct {
	apiserverv1.JWTAuthenticator `json:",inline"`

	SigningAlgs []string `json:"signingAlgs,omitempty"`

	// PublicKeys is PEM: PUBLIC KEY blocks, or CERTIFICATE blocks whose
	// public key is used.
	PublicKeys string `json:"publicKeys,omitempty"`
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

		var keys []crypto.PublicKey
		if publicKeys := file.Issuers[i].PublicKeys; len(publicKeys) > 0 {
			// Nothing is fetched from an issuer whose keys are given, so
			// settings that only shape that fetch would be quietly ignored.
			if len(jwtAuthenticator.Issuer.CertificateAuthority) > 0 {
				return nil, fmt.Errorf("--oidc-config-file: issuers[%d]: issuer.certificateAuthority cannot be used with publicKeys", i)
			}

			if len(jwtAuthenticator.Issuer.DiscoveryURL) > 0 {
				return nil, fmt.Errorf("--oidc-config-file: issuers[%d]: issuer.discoveryURL cannot be used with publicKeys", i)
			}

			keys, err = parsePublicKeys([]byte(publicKeys), algs)
			if err != nil {
				return nil, fmt.Errorf("--oidc-config-file: issuers[%d].publicKeys: %w", i, err)
			}
		}

		issuers = append(issuers, Issuer{
			JWTAuthenticator: jwtAuthenticator,
			SigningAlgs:      algs,
			PublicKeys:       keys,
		})
	}

	return issuers, nil
}

// parsePublicKeys reads the keys out of PEM PUBLIC KEY and CERTIFICATE blocks.
// Only a certificate's public key is used: its validity, chain and revocation
// are not checked, since listing it here is what trusts it.
func parsePublicKeys(data []byte, signingAlgs []string) ([]crypto.PublicKey, error) {
	var keys []crypto.PublicKey
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		var (
			key crypto.PublicKey
			err error
		)
		switch block.Type {
		case "PUBLIC KEY":
			key, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "CERTIFICATE":
			var cert *x509.Certificate
			cert, err = x509.ParseCertificate(block.Bytes)
			if err == nil {
				key = cert.PublicKey
			}
		default:
			return nil, fmt.Errorf("unsupported PEM block %q, must be PUBLIC KEY or CERTIFICATE", block.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", len(keys), err)
		}

		// A key that none of the issuer's algorithms can verify with would
		// reject every token signed with it, without saying why.
		if !keyMatchesAlgs(key, signingAlgs) {
			return nil, fmt.Errorf("key %d: a %T cannot verify any of signingAlgs %v", len(keys), key, signingAlgs)
		}

		keys = append(keys, key)
	}

	if len(strings.TrimSpace(string(data))) > 0 {
		return nil, errors.New("contains data that is not a PEM block")
	}

	if len(keys) == 0 {
		return nil, errors.New("contains no PEM blocks")
	}

	return keys, nil
}

// keyMatchesAlgs reports whether the key can verify a signature made with any
// of the algorithms.
func keyMatchesAlgs(key crypto.PublicKey, signingAlgs []string) bool {
	for _, alg := range signingAlgs {
		switch key.(type) {
		case *rsa.PublicKey:
			if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
				return true
			}
		case *ecdsa.PublicKey:
			if strings.HasPrefix(alg, "ES") {
				return true
			}
		}
	}

	return false
}

func (o *OIDCAuthenticationOptions) AddFlags(fs *pflag.FlagSet) *OIDCAuthenticationOptions {
	fs.StringVar(&o.ConfigFile, "oidc-config-file", o.ConfigFile, ""+
		"Path to a YAML file listing every issuer to trust under issuers. Each issuer takes the "+
		"fields of a jwt entry of kube-apiserver's --authentication-config, signingAlgs, the "+
		"JOSE algorithms its tokens may be signed with (default [RS256]), and optionally "+
		"publicKeys, PEM keys or certificates to verify its tokens with instead of fetching its keys.")

	return o
}
