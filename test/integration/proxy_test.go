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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/cmd/app"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy"
	"github.com/jetstack/kube-oidc-proxy/pkg/util"
	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework/helper"
	fakeapiserver "github.com/jetstack/kube-oidc-proxy/test/tools/fake-apiserver/pkg/server"
	"github.com/jetstack/kube-oidc-proxy/test/tools/issuer/pkg/issuer"
	testutil "github.com/jetstack/kube-oidc-proxy/test/util"
)

func TestJWTAuthenticationWithLDAPGroupsIsForwardedToAPIServer(t *testing.T) {
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

	oidcServer := httptest.NewUnstartedServer(nil)
	issuerURL := "https://" + oidcServer.Listener.Addr().String()
	oidcHandler, err := issuer.New(issuerURL, keyPath, certPath, stopComponents)
	if err != nil {
		t.Fatalf("failed to create mock OIDC issuer: %s", err)
	}
	oidcServer.Config.Handler = oidcHandler
	oidcServer.StartTLS()
	t.Cleanup(oidcServer.Close)
	issuerCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oidcServer.Certificate().Raw})
	issuerCAPath := writeFile(t, testDir, "issuer-ca.crt", issuerCA)

	primaryLDAP := newMockLDAPServer(t, "platform-admins", "all-staff")
	secondaryLDAP := newMockLDAPServer(t, "engineering", "all-staff")
	ldapConfig := fmt.Sprintf(`{
  "backends": [
  {
    "name": "primary",
    "urls": [%q],
    "bindDN": %q,
    "bindPassword": %q,
    "userSearchBases": [%q],
    "groupSearchBases": [%q]
  },
  {
    "name": "secondary",
    "urls": [%q],
    "bindDN": %q,
    "bindPassword": %q,
    "userSearchBases": [%q],
    "groupSearchBases": [%q]
  }],
  "refreshInterval": "1h",
  "cache": {"type": "none"}
}`, primaryLDAP.URL(), bindDN, bindPassword, userBase, groupBase,
		secondaryLDAP.URL(), bindDN, bindPassword, userBase, groupBase)
	ldapConfigPath := writeFile(t, testDir, "ldap.json", []byte(ldapConfig))

	proxyPort := freePort(t)
	readinessPort := freePort(t)
	clientID := "kube-oidc-proxy-integration"
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
		"--oidc-issuer-url=" + oidcServer.URL,
		"--oidc-client-id=" + clientID,
		"--oidc-ca-file=" + issuerCAPath,
		"--oidc-username-claim=email",
		"--oidc-groups-claim=groups",
		"--ldap-config-file=" + ldapConfigPath,
	})

	commandErr := make(chan error, 1)
	go func() { commandErr <- command.Execute() }()

	waitForReady(t, "http://127.0.0.1:"+readinessPort+"/ready", commandErr)
	primaryLDAP.AssertRequests(t, 1, 1, 1)
	secondaryLDAP.AssertRequests(t, 1, 1, 1)

	tokenPayload := []byte(fmt.Sprintf(`{
  "iss": %q,
  "aud": [%q],
  "email": "alice@example.com",
  "groups": ["jwt-only-group"],
  "exp": %d
}`, oidcServer.URL, clientID, time.Now().Add(10*time.Minute).Unix()))
	token, err := new(helper.Helper).SignToken(bundle, tokenPayload)
	if err != nil {
		t.Fatalf("failed to sign JWT: %s", err)
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(bundle.CertBytes) {
		t.Fatal("failed to trust proxy certificate")
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}},
	}

	proxyURL := "https://127.0.0.1:" + proxyPort
	request := func(method, path string) *http.Response {
		t.Helper()

		req, err := http.NewRequest(method, proxyURL+path, nil)
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

	apiPath := "/api/v1/namespaces/default/pods?limit=1"
	assertIdentity(t, request(http.MethodGet, apiPath),
		"all-staff", "engineering", "platform-admins", "system:authenticated")

	primaryLDAP.AddUserToNewGroup("release-managers")

	// The directory changed, but requests continue to use the complete mapping
	// built at startup until a refresh replaces it.
	assertIdentity(t, request(http.MethodGet, apiPath),
		"all-staff", "engineering", "platform-admins", "system:authenticated")
	primaryLDAP.AssertRequests(t, 1, 1, 1)
	secondaryLDAP.AssertRequests(t, 1, 1, 1)

	refreshResponse := request(http.MethodPost, proxy.LDAPRefreshPath)
	if refreshResponse.StatusCode != http.StatusOK {
		t.Fatalf("LDAP refresh response status = %d, want %d",
			refreshResponse.StatusCode, http.StatusOK)
	}
	primaryLDAP.AssertRequests(t, 2, 2, 2)
	secondaryLDAP.AssertRequests(t, 2, 2, 2)

	assertIdentity(t, request(http.MethodGet, apiPath),
		"all-staff", "engineering", "platform-admins", "release-managers", "system:authenticated")

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

func assertIdentity(t *testing.T, response *http.Response, groups ...string) {
	t.Helper()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("proxy response status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := response.Header.Get("Impersonate-User"); got != "alice@example.com" {
		t.Errorf("API server received Impersonate-User %q, want %q", got, "alice@example.com")
	}

	gotGroups := append([]string(nil), response.Header.Values("Impersonate-Group")...)
	sort.Strings(gotGroups)
	sort.Strings(groups)
	if !reflect.DeepEqual(gotGroups, groups) {
		t.Errorf("API server received Impersonate-Group %v, want LDAP-derived groups %v", gotGroups, groups)
	}
	if strings.Contains(strings.Join(gotGroups, ","), "jwt-only-group") {
		t.Errorf("API server received a group from the JWT instead of LDAP: %v", gotGroups)
	}
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write %s: %s", name, err)
	}
	return path
}

func freePort(t *testing.T) string {
	t.Helper()
	port, err := util.FreePort()
	if err != nil {
		t.Fatalf("failed to find a free port: %s", err)
	}
	return port
}

func waitForReady(t *testing.T, readyURL string, commandErr <-chan error) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-commandErr:
			t.Fatalf("proxy exited before becoming ready: %v", err)
		default:
		}

		response, err := http.Get(readyURL)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}

		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("proxy did not become ready at %s within 15s", readyURL)
}
