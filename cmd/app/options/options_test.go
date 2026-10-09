// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const oneIssuer = `issuers:
- issuer:
    url: https://a.example.com
    audiences: [proxy-a]
  claimMappings:
    username:
      claim: email
      prefix: ""
`

const oneBackend = `{"backends": [{
  "name": "corp",
  "urls": ["ldaps://ldap.example.net:636"],
  "userSearchBases": ["OU=Users,DC=example,DC=net"],
  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]
}]}`

func validate(t *testing.T, args ...string) error {
	t.Helper()

	opts := New()
	cmd := &cobra.Command{}
	opts.AddFlags(cmd)
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatalf("unexpected error parsing flags: %s", err)
	}

	return opts.Validate(cmd)
}

func TestValidateProxyModes(t *testing.T) {
	oidcConfig := "--oidc-config-file=" + writeFile(t, "authn.yaml", oneIssuer)
	ldapConfig := "--ldap-config-file=" + writeFile(t, "ldap.json", oneBackend)

	tests := map[string]struct {
		args   []string
		expErr string
	}{
		"impersonation with token groups": {
			args: []string{oidcConfig},
		},
		"impersonation with directory groups": {
			args: []string{oidcConfig, ldapConfig},
		},
		"impersonation needs issuers to authenticate with": {
			args:   []string{},
			expErr: "--oidc-config-file is required",
		},
		// The API server authenticates passthrough requests, so the proxy
		// needs no issuers, and ignores any it is given.
		"passthrough without issuers": {
			args: []string{"--token-passthrough"},
		},
		"passthrough with issuers": {
			args: []string{"--token-passthrough", oidcConfig},
		},
		"passthrough with directory groups": {
			args:   []string{"--token-passthrough", oidcConfig, ldapConfig},
			expErr: "--token-passthrough cannot be used with --ldap-config-file",
		},
		"passthrough with a client IP extra": {
			args:   []string{"--token-passthrough", "--extra-user-header-client-ip"},
			expErr: "--token-passthrough cannot be used with extra user headers",
		},
		"passthrough with extra user headers": {
			args:   []string{"--token-passthrough", "--extra-user-headers=foo=bar"},
			expErr: "--token-passthrough cannot be used with extra user headers",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validate(t, test.args...)
			if test.expErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.expErr) {
				t.Fatalf("expected an error containing %q, got %v", test.expErr, err)
			}
		})
	}
}

func TestRemovedFlagsAreRejected(t *testing.T) {
	for _, flag := range []string{"--disable-impersonation", "--token-passthrough-audiences=aud"} {
		opts := New()
		cmd := &cobra.Command{}
		opts.AddFlags(cmd)
		if err := cmd.Flags().Parse([]string{flag}); err == nil {
			t.Errorf("expected the removed flag %s to be rejected", flag)
		}
	}
}
