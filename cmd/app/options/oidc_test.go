// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"k8s.io/apiserver/pkg/apis/apiserver"
)

func parseOIDCFlags(t *testing.T, args ...string) *OIDCAuthenticationOptions {
	t.Helper()

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o := new(OIDCAuthenticationOptions).AddFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("unexpected error parsing flags: %s", err)
	}

	return o
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("unexpected error writing %s: %s", name, err)
	}

	return path
}

const twoIssuers = `issuers:
- issuer:
    url: https://a.example.com
    audiences: [proxy-a]
  claimMappings:
    username:
      claim: email
      prefix: "a:"
- issuer:
    url: https://b.example.com
    audiences: [proxy-b]
  signingAlgs: [ES256, RS256]
  claimValidationRules:
  - claim: hd
    requiredValue: example.com
  claimMappings:
    username:
      claim: sub
      prefix: "b:"
`

func TestConfigFileTrustsEveryIssuer(t *testing.T) {
	o := parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml", twoIssuers))

	if err := o.Validate(); err != nil {
		t.Fatalf("unexpected error validating: %s", err)
	}

	issuers, err := o.Issuers()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var urls []string
	for _, issuer := range issuers {
		urls = append(urls, issuer.JWTAuthenticator.Issuer.URL)
	}

	if exp := []string{"https://a.example.com", "https://b.example.com"}; !reflect.DeepEqual(urls, exp) {
		t.Errorf("expected issuers %v, got %v", exp, urls)
	}

	// a names no algorithms, so it is held to RS256.
	if got, exp := issuers[0].SigningAlgs, []string{"RS256"}; !reflect.DeepEqual(got, exp) {
		t.Errorf("expected issuer a to allow %v, got %v", exp, got)
	}

	if got, exp := issuers[1].SigningAlgs, []string{"ES256", "RS256"}; !reflect.DeepEqual(got, exp) {
		t.Errorf("expected issuer b to allow %v, got %v", exp, got)
	}

	exp := []apiserver.ClaimValidationRule{{Claim: "hd", RequiredValue: "example.com"}}
	if got := issuers[1].JWTAuthenticator.ClaimValidationRules; !reflect.DeepEqual(got, exp) {
		t.Errorf("expected claim validation rules %v, got %v", exp, got)
	}
}

func TestConfigFileInvalid(t *testing.T) {
	const (
		issuerA  = "- issuer:\n    url: https://a.example.com\n    audiences: [a]\n"
		username = "  claimMappings:\n    username:\n      claim: sub\n      prefix: \"\"\n"
	)

	tests := map[string]struct {
		config string
		expErr string
	}{
		"empty": {
			config: "",
			expErr: "at least one issuer is required",
		},
		"no issuers": {
			config: "issuers: []\n",
			expErr: "at least one issuer is required",
		},
		// A kube-apiserver AuthenticationConfiguration is not read as one.
		"authentication configuration": {
			config: "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\njwt:\n" +
				issuerA + username,
			expErr: "list them under issuers instead",
		},
		"duplicate issuer": {
			config: "issuers:\n" + issuerA + username +
				"- issuer:\n    url: https://a.example.com\n    audiences: [b]\n" + username,
			expErr: "Duplicate value",
		},
		// kube-apiserver requires the prefix be given whenever the claim is.
		"username claim without a prefix": {
			config: "issuers:\n" + issuerA + "  claimMappings:\n    username:\n      claim: sub\n",
			expErr: "prefix",
		},
		"issuer without https": {
			config: "issuers:\n- issuer:\n    url: http://a.example.com\n    audiences: [a]\n" + username,
			expErr: "https",
		},
		"unsupported signing algorithm": {
			config: "issuers:\n" + issuerA + "  signingAlgs: [HS256]\n" + username,
			expErr: `unsupported signing algorithm "HS256"`,
		},
		"empty signing algorithms": {
			config: "issuers:\n" + issuerA + "  signingAlgs: []\n" + username,
			expErr: "signingAlgs must not be empty",
		},
		"signing algorithms not a list": {
			config: "issuers:\n" + issuerA + "  signingAlgs: RS256\n" + username,
			expErr: "signingAlgs",
		},
		// Errors kube-apiserver's validation finds name the field as it is
		// in this file.
		"field path": {
			config: "issuers:\n" + issuerA + username +
				"- issuer:\n    url: http://b.example.com\n    audiences: [b]\n" + username,
			expErr: "issuers[1].issuer.url",
		},
		"unknown field": {
			config: "issuers:\n" + issuerA + "    audience: typo\n" + username,
			expErr: "unknown field",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o := parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml", test.config))

			if err := o.Validate(); err == nil || !strings.Contains(err.Error(), test.expErr) {
				t.Errorf("expected error containing %q, got %v", test.expErr, err)
			}
		})
	}
}

// The fields of an issuer are kube-apiserver's, CEL expressions included.
func TestConfigFileExpressionMappings(t *testing.T) {
	o := parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml", `issuers:
- issuer:
    url: https://a.example.com
    audiences: [a]
  claimMappings:
    username:
      expression: '"a:" + claims.sub'
  userValidationRules:
  - expression: "!user.username.startsWith('system:')"
    message: username cannot use the reserved system prefix
`))

	issuers, err := o.Issuers()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if got, exp := issuers[0].JWTAuthenticator.ClaimMappings.Username.Expression, `"a:" + claims.sub`; got != exp {
		t.Errorf("expected username expression %q, got %q", exp, got)
	}

	if got := len(issuers[0].JWTAuthenticator.UserValidationRules); got != 1 {
		t.Errorf("expected 1 user validation rule, got %d", got)
	}
}

func TestNoIssuer(t *testing.T) {
	if err := parseOIDCFlags(t).Validate(); err == nil ||
		!strings.Contains(err.Error(), "--oidc-config-file is required") {
		t.Errorf("expected an error asking for an issuer, got %v", err)
	}
}

func TestSharedUsernamePrefix(t *testing.T) {
	single := twoIssuers[:strings.Index(twoIssuers, "- issuer:\n    url: https://b.example.com")]
	o := parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml", single))
	if prefix, err := o.SharedUsernamePrefix(); err != nil || prefix != "a:" {
		t.Errorf("expected prefix %q, got %q (err=%v)", "a:", prefix, err)
	}

	// Issuers a: and b: prefix their usernames differently, so there is no
	// one prefix to take off before a directory lookup.
	o = parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml", twoIssuers))
	if _, err := o.SharedUsernamePrefix(); err == nil {
		t.Error("expected an error for issuers with different username prefixes")
	}

	shared := strings.ReplaceAll(twoIssuers, `prefix: "b:"`, `prefix: "a:"`)
	o = parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml", shared))
	if prefix, err := o.SharedUsernamePrefix(); err != nil || prefix != "a:" {
		t.Errorf("expected prefix %q, got %q (err=%v)", "a:", prefix, err)
	}
}

func pemPublicKey(t *testing.T, key crypto.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("unexpected error marshalling public key: %s", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func pemCertificate(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()

	// Long expired: only the key in a certificate is used.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("unexpected error creating certificate: %s", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// indentBlock indents every line of a PEM bundle to nest in a YAML block
// scalar.
func indentBlock(s, prefix string) string {
	return prefix + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n"+prefix)
}

func publicKeysConfig(publicKeys, extra string) string {
	return "issuers:\n- issuer:\n    url: https://a.example.com\n    audiences: [a]\n" + extra +
		"  publicKeys: |\n" + indentBlock(publicKeys, "    ") + "\n" +
		"  claimMappings:\n    username:\n      claim: sub\n      prefix: \"\"\n"
}

func TestConfigFilePublicKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error generating key: %s", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error generating key: %s", err)
	}

	bundle := pemPublicKey(t, &rsaKey.PublicKey) + pemCertificate(t, rsaKey) + pemPublicKey(t, &ecKey.PublicKey)
	o := parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml",
		publicKeysConfig(bundle, "  signingAlgs: [RS256, ES256]\n")))

	issuers, err := o.Issuers()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	exp := []crypto.PublicKey{&rsaKey.PublicKey, &rsaKey.PublicKey, &ecKey.PublicKey}
	if got := issuers[0].PublicKeys; !reflect.DeepEqual(got, exp) {
		t.Errorf("expected the keys of the bundle, got %v", got)
	}

	// Without publicKeys, keys are fetched from the issuer.
	o = parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml", twoIssuers))
	issuers, err = o.Issuers()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if issuers[0].PublicKeys != nil {
		t.Errorf("expected no public keys, got %v", issuers[0].PublicKeys)
	}
}

func TestConfigFilePublicKeysInvalid(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error generating key: %s", err)
	}
	rsaPEM := pemPublicKey(t, &rsaKey.PublicKey)

	privatePEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))

	tests := map[string]struct {
		config string
		expErr string
	}{
		"not PEM": {
			config: publicKeysConfig("not a key", ""),
			expErr: "not a PEM block",
		},
		"trailing data": {
			config: publicKeysConfig(rsaPEM+"garbage", ""),
			expErr: "not a PEM block",
		},
		"private key": {
			config: publicKeysConfig(privatePEM, ""),
			expErr: `unsupported PEM block "RSA PRIVATE KEY"`,
		},
		"corrupt key": {
			config: publicKeysConfig("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", ""),
			expErr: "key 0",
		},
		// An RSA key cannot verify an ES256 signature, so every token would
		// be rejected.
		"key no algorithm can use": {
			config: publicKeysConfig(rsaPEM, "  signingAlgs: [ES256]\n"),
			expErr: "cannot verify any of signingAlgs",
		},
		"with a CA": {
			config: strings.Replace(publicKeysConfig(rsaPEM, ""), "    audiences: [a]\n",
				"    audiences: [a]\n    certificateAuthority: |\n"+indentBlock(pemCertificate(t, rsaKey), "      ")+"\n", 1),
			expErr: "certificateAuthority cannot be used with publicKeys",
		},
		"with a discovery URL": {
			config: strings.Replace(publicKeysConfig(rsaPEM, ""), "    audiences: [a]\n",
				"    audiences: [a]\n    discoveryURL: https://discovery.example.com/.well-known/openid-configuration\n", 1),
			expErr: "discoveryURL cannot be used with publicKeys",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o := parseOIDCFlags(t, "--oidc-config-file="+writeFile(t, "authn.yaml", test.config))

			if err := o.Validate(); err == nil || !strings.Contains(err.Error(), test.expErr) {
				t.Errorf("expected error containing %q, got %v", test.expErr, err)
			}
		})
	}
}
