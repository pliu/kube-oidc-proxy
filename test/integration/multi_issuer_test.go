// Copyright Jetstack Ltd. See LICENSE for details.
package integration

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/cmd/app"
	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework/helper"
	fakeapiserver "github.com/jetstack/kube-oidc-proxy/test/tools/fake-apiserver/pkg/server"
	"github.com/jetstack/kube-oidc-proxy/test/tools/issuer/pkg/issuer"
	testutil "github.com/jetstack/kube-oidc-proxy/test/util"
)

type testIssuer struct {
	url    string
	ca     []byte
	signer *testutil.KeyBundle
}

// startIssuer serves an OIDC issuer over TLS whose tokens are signed by a key
// of its own.
func startIssuer(t *testing.T, dir, name string, stopCh <-chan struct{}) *testIssuer {
	t.Helper()

	signer, err := testutil.NewTLSSelfSignedCertKey("127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatalf("failed to create signing key for issuer %s: %s", name, err)
	}

	server := httptest.NewUnstartedServer(nil)
	url := "https://" + server.Listener.Addr().String()
	handler, err := issuer.New(url,
		writeFile(t, dir, name+"-signer.key", signer.KeyBytes),
		writeFile(t, dir, name+"-signer.crt", signer.CertBytes),
		stopCh)
	if err != nil {
		t.Fatalf("failed to create mock OIDC issuer %s: %s", name, err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	t.Cleanup(server.Close)

	return &testIssuer{
		url:    url,
		ca:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		signer: signer,
	}
}

// indent prefixes every line of a PEM bundle so it nests in a YAML block
// scalar.
func indent(pemBytes []byte, prefix string) string {
	return prefix + strings.ReplaceAll(strings.TrimSpace(string(pemBytes)), "\n", "\n"+prefix)
}

func TestConfigFileTrustsEveryListedIssuer(t *testing.T) {
	testDir := t.TempDir()
	bundle, err := testutil.NewTLSSelfSignedCertKey("127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatalf("failed to create test certificates: %s", err)
	}

	certPath := writeFile(t, testDir, "tls.crt", bundle.CertBytes)
	keyPath := writeFile(t, testDir, "tls.key", bundle.KeyBytes)

	stopComponents := make(chan struct{})
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
	// Serves discovery and keys like the others, but is not in the file.
	untrusted := startIssuer(t, testDir, "untrusted", stopComponents)

	// Each issuer is verified against its own CA, and B additionally requires
	// a claim.
	authnConfig := fmt.Sprintf(`issuers:
- issuer:
    url: %s
    audiences: [client-a]
    certificateAuthority: |
%s
  claimMappings:
    username:
      claim: email
      prefix: "a:"
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
      claim: email
      prefix: "b:"
- issuer:
    url: %s
    audiences: [client-c]
    certificateAuthority: |
%s
  signingAlgs: [ES256]
  claimMappings:
    username:
      claim: email
      prefix: "c:"
`, issuerA.url, indent(issuerA.ca, "      "), issuerB.url, indent(issuerB.ca, "      "),
		issuerC.url, indent(issuerC.ca, "      "))
	authnConfigPath := writeFile(t, testDir, "authn.yaml", []byte(authnConfig))

	proxyPort := freePort(t)
	readinessPort := freePort(t)
	proxyStop := make(chan struct{})
	var stopOnce sync.Once
	t.Cleanup(func() {
		stopOnce.Do(func() { close(proxyStop) })
		close(stopComponents)
	})

	command := app.NewRunCommand(proxyStop)
	command.SetArgs([]string{
		"--server=" + apiServer.URL,
		"--bind-address=127.0.0.1",
		"--secure-port=" + proxyPort,
		"--tls-cert-file=" + certPath,
		"--tls-private-key-file=" + keyPath,
		"--readiness-probe-port=" + readinessPort,
		"--oidc-config-file=" + authnConfigPath,
	})

	commandErr := make(chan error, 1)
	go func() { commandErr <- command.Execute() }()

	// Ready only once every issuer's keys have been fetched.
	waitForReady(t, "http://127.0.0.1:"+readinessPort+"/ready", commandErr)

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(bundle.CertBytes) {
		t.Fatal("failed to trust proxy certificate")
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}},
	}

	request := func(signer *testutil.KeyBundle, claims string) *http.Response {
		t.Helper()

		token, err := new(helper.Helper).SignToken(signer, []byte(fmt.Sprintf(`{
  "email": "alice@example.com",
  "exp": %d,
  %s
}`, time.Now().Add(10*time.Minute).Unix(), claims)))
		if err != nil {
			t.Fatalf("failed to sign JWT: %s", err)
		}

		req, err := http.NewRequest(http.MethodGet,
			"https://127.0.0.1:"+proxyPort+"/api/v1/namespaces/default/pods?limit=1", nil)
		if err != nil {
			t.Fatalf("failed to create proxy request: %s", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		response, err := client.Do(req)
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
			expUser: "a:alice@example.com",
		},
		"a token from the second issuer": {
			signer:  issuerB.signer,
			claims:  fmt.Sprintf(`"iss": %q, "aud": "client-b", "tenant": "b"`, issuerB.url),
			expCode: http.StatusOK,
			expUser: "b:alice@example.com",
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

	stopOnce.Do(func() { close(proxyStop) })
	select {
	case err := <-commandErr:
		if err != nil {
			t.Fatalf("proxy stopped with an error: %s", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("proxy did not stop within 10s")
	}
}
