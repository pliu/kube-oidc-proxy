// Copyright Jetstack Ltd. See LICENSE for details.
package integration

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework/helper"
	fakeapiserver "github.com/jetstack/kube-oidc-proxy/test/tools/fake-apiserver/pkg/server"
	testutil "github.com/jetstack/kube-oidc-proxy/test/util"
)

func TestConfigFileTrustsEveryListedIssuer(t *testing.T) {
	testDir := t.TempDir()
	bundle, certPath, keyPath := testCertificates(t, testDir)
	stopComponents := componentStop(t)
	apiHandler, err := fakeapiserver.New(keyPath, certPath, stopComponents)
	if err != nil {
		t.Fatalf("failed to create mock API server: %s", err)
	}
	apiServer := httptest.NewServer(apiHandler)
	t.Cleanup(apiServer.Close)

	issuerA := startIssuer(t, testDir, "a", stopComponents)
	issuerB := startIssuer(t, testDir, "b", stopComponents)
	// Only accepts ES256, while every signer here signs RS256.
	issuerC := startIssuer(t, testDir, "c", stopComponents)
	// Its keys are in the file, and nothing listens at its URL: a proxy that
	// tried to fetch them could never become ready.
	staticURL := "https://127.0.0.1:" + freePort(t)
	staticSigner, err := testutil.NewTLSSelfSignedCertKey("127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatalf("failed to create signing key for the static issuer: %s", err)
	}

	// Serves discovery and keys like the others, but is not in the file.
	untrusted := startIssuer(t, testDir, "untrusted", stopComponents)

	// Each issuer is verified against its own CA, and B additionally requires
	// a claim.
	authnConfig := fmt.Sprintf(`usernamePrefix: "oidc:"
issuers:
- issuer:
    url: %s
    audiences: [client-a]
    certificateAuthority: |
%s
  claimMappings:
    username:
      claim: email
- issuer:
    url: %s
    audiences: [client-b]
    certificateAuthority: |
%s
  claimValidationRules:
  - claim: tenant
    requiredValue: b
  claimMappings:
    username:
      expression: claims.sub
- issuer:
    url: %s
    audiences: [client-c]
    certificateAuthority: |
%s
  signingAlgs: [ES256]
  claimMappings:
    username:
      claim: email
- issuer:
    url: %s
    audiences: [client-static]
  publicKeys: |
%s
  claimMappings:
    username:
      claim: email
`, issuerA.url, indent(issuerA.ca, "      "), issuerB.url, indent(issuerB.ca, "      "),
		issuerC.url, indent(issuerC.ca, "      "), staticURL, indent(staticSigner.CertBytes, "    "))
	authnConfigPath := writeFile(t, testDir, "authn.yaml", []byte(authnConfig))

	proxyServer := startTestProxy(t, testProxyConfig{
		apiURL: apiServer.URL, certPath: certPath, keyPath: keyPath, ca: bundle.CertBytes,
		authnConfigPath: authnConfigPath,
	})

	request := func(signer *testutil.KeyBundle, claims string) *http.Response {
		t.Helper()

		token, err := new(helper.Helper).SignToken(signer, []byte(fmt.Sprintf(`{
  "email": "alice@example.com",
  "sub": "alice@example.com",
  "exp": %d,
  %s
}`, time.Now().Add(10*time.Minute).Unix(), claims)))
		if err != nil {
			t.Fatalf("failed to sign JWT: %s", err)
		}

		req, err := http.NewRequest(http.MethodGet,
			proxyServer.url+"/api/v1/namespaces/default/pods?limit=1", nil)
		if err != nil {
			t.Fatalf("failed to create proxy request: %s", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		response, err := proxyServer.client.Do(req)
		if err != nil {
			t.Fatalf("request through proxy failed: %s", err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return response
	}

	tests := map[string]struct {
		signer  *testutil.KeyBundle
		claims  string
		expCode int
		expUser string
	}{
		"a token from the first issuer": {
			signer:  issuerA.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-a"`, issuerA.url),
			expCode: http.StatusOK,
			expUser: "oidc:alice@example.com",
		},
		"a token from the second issuer": {
			signer:  issuerB.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-b", "tenant": "b"`, issuerB.url),
			expCode: http.StatusOK,
			expUser: "oidc:alice@example.com",
		},
		"a token from an issuer with its keys in the file": {
			signer:  staticSigner,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-static"`, staticURL),
			expCode: http.StatusOK,
			expUser: "oidc:alice@example.com",
		},
		"a token naming the issuer with its keys in the file but signed by another's key": {
			signer:  issuerA.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-static"`, staticURL),
			expCode: http.StatusUnauthorized,
		},
		"a token from an issuer not in the file": {
			signer:  untrusted.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-a"`, untrusted.url),
			expCode: http.StatusUnauthorized,
		},
		"a token naming one trusted issuer but signed by another's key": {
			signer:  issuerA.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-b", "tenant": "b"`, issuerB.url),
			expCode: http.StatusUnauthorized,
		},
		"a token for another issuer's audience": {
			signer:  issuerA.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-b"`, issuerA.url),
			expCode: http.StatusUnauthorized,
		},
		"a token signed with an algorithm its issuer does not allow": {
			signer:  issuerC.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-c"`, issuerC.url),
			expCode: http.StatusUnauthorized,
		},
		"a token without the claim its issuer requires": {
			signer:  issuerB.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-b", "tenant": "a"`, issuerB.url),
			expCode: http.StatusUnauthorized,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			response := request(test.signer, test.claims)
			if response.StatusCode != test.expCode {
				t.Fatalf("proxy response status = %d, want %d", response.StatusCode, test.expCode)
			}

			if test.expUser == "" {
				return
			}

			if got := response.Header.Get("Impersonate-User"); got != test.expUser {
				t.Errorf("API server received Impersonate-User %q, want %q", got, test.expUser)
			}
		})
	}

	proxyServer.stop()
}
