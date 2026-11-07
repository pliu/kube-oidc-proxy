// Copyright Jetstack Ltd. See LICENSE for details.
package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"sigs.k8s.io/yaml"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework/helper"
	fakeapiserver "github.com/jetstack/kube-oidc-proxy/test/tools/fake-apiserver/pkg/server"
)

func TestJWTAuthenticationWithLDAPGroupsIsForwardedToAPIServer(t *testing.T) {
	testDir := t.TempDir()
	bundle, certPath, keyPath := testCertificates(t, testDir)
	stopComponents := componentStop(t)
	apiHandler, err := fakeapiserver.New(keyPath, certPath, stopComponents)
	if err != nil {
		t.Fatalf("failed to create mock API server: %s", err)
	}
	persistence := &cacheAPI{records: make(map[string]corev1.ConfigMap)}
	apiServer := httptest.NewServer(persistence.wrap(apiHandler))
	t.Cleanup(apiServer.Close)

	oidc := startIssuer(t, testDir, "oidc", stopComponents)

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
  "cache": {"namespace": "proxy"}
}`, primaryLDAP.URL(), bindDN, bindPassword, userBase, groupBase,
		secondaryLDAP.URL(), bindDN, bindPassword, userBase, groupBase)
	ldapConfigPath := writeFile(t, testDir, "ldap.json", []byte(ldapConfig))

	clientID := "kube-oidc-proxy-integration"
	authnConfig := fmt.Sprintf(`usernamePrefix: "oidc:"
issuers:
- issuer:
    url: %s
    audiences: [%s]
    certificateAuthority: |
%s
  claimMappings:
    username:
      claim: email
    groups:
      claim: groups
      prefix: ""
`, oidc.url, clientID, indent(oidc.ca, "      "))
	authnConfigPath := writeFile(t, testDir, "authn.yaml", []byte(authnConfig))

	auditPath := filepath.Join(testDir, "audit.log")
	policy := writeFile(t, testDir, "audit-policy.yaml", []byte("apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: Metadata\n"))
	proxyServer := startTestProxy(t, testProxyConfig{
		apiURL: apiServer.URL, certPath: certPath, keyPath: keyPath, ca: bundle.CertBytes,
		authnConfigPath: authnConfigPath,
		extraArgs: []string{"--ldap-config-file=" + ldapConfigPath,
			"--audit-policy-file=" + policy, "--audit-log-path=" + auditPath, "--audit-log-mode=blocking"},
	})
	primaryLDAP.AssertRequests(t, 0, 0, 0)
	secondaryLDAP.AssertRequests(t, 0, 0, 0)

	tokenPayload := []byte(fmt.Sprintf(`{
  "iss": %q,
  "aud": [%q],
  "email": "alice@example.com",
  "groups": ["jwt-only-group"],
  "exp": %d
}`, oidc.url, clientID, time.Now().Add(10*time.Minute).Unix()))
	token, err := new(helper.Helper).SignToken(oidc.signer, tokenPayload)
	if err != nil {
		t.Fatalf("failed to sign JWT: %s", err)
	}

	request := func(method, path string) *http.Response {
		t.Helper()

		req, err := http.NewRequest(method, proxyServer.url+path, nil)
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

	apiPath := "/api/v1/namespaces/default/pods?limit=1"
	assertIdentity(t, request(http.MethodGet, apiPath),
		"all-staff", "engineering", "platform-admins", "system:authenticated")

	primaryLDAP.AddUserToNewGroup("release-managers")

	// Memberships changed in LDAP, but cache hits still serve the record
	// persisted by the first authenticated request until it is refreshed.
	assertIdentity(t, request(http.MethodGet, apiPath),
		"all-staff", "engineering", "platform-admins", "system:authenticated")
	primaryLDAP.AssertRequests(t, 1, 2, 1)
	secondaryLDAP.AssertRequests(t, 1, 2, 1)

	// The refresh endpoint is a stub for now: it answers, but does not search
	// the directories again, so the cached memberships are unchanged.
	refreshResponse := request(http.MethodPost, proxy.LDAPRefreshPath)
	if refreshResponse.StatusCode != http.StatusOK {
		t.Fatalf("LDAP refresh response status = %d, want %d",
			refreshResponse.StatusCode, http.StatusOK)
	}
	primaryLDAP.AssertRequests(t, 1, 2, 1)
	secondaryLDAP.AssertRequests(t, 1, 2, 1)

	assertIdentity(t, request(http.MethodGet, apiPath),
		"all-staff", "engineering", "platform-admins", "system:authenticated")

	persistence.mu.Lock()
	var persistedGroups []string
	for _, cm := range persistence.records {
		var identity struct {
			Username                 string `json:"username"`
			ConfigurationFingerprint string `json:"configurationFingerprint"`
		}
		// Decode with the configuration fingerprint carried by this generated record.
		raw := []byte(cm.Data[cache.UserRecordKey])
		var record cache.UserRecord
		if err := yaml.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		identity.Username = record.Username
		identity.ConfigurationFingerprint = record.ConfigurationFingerprint
		checked, err := cache.DecodeUserRecord(raw, identity.Username, identity.ConfigurationFingerprint)
		if err != nil {
			t.Fatal(err)
		}
		persistedGroups = checked.Groups
	}
	persistence.mu.Unlock()
	wantPersisted := []string{"all-staff", "engineering", "platform-admins"}
	if !reflect.DeepEqual(persistedGroups, wantPersisted) {
		t.Fatalf("persisted groups %v", persistedGroups)
	}
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	matched := false
	for scanner.Scan() {
		var event auditv1.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.RequestURI != apiPath {
			continue
		}
		groups := append([]string{}, event.User.Groups...)
		sort.Strings(groups)
		expected := append([]string{}, persistedGroups...)
		sort.Strings(expected)
		if !reflect.DeepEqual(groups, expected) {
			t.Fatalf("audit groups %v differ from persisted %v", groups, expected)
		}
		matched = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("no audit event for forwarded request")
	}
	proxyServer.stop()
}

func assertIdentity(t *testing.T, response *http.Response, groups ...string) {
	t.Helper()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("proxy response status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := response.Header.Get("Impersonate-User"); got != "oidc:alice@example.com" {
		t.Errorf("API server received Impersonate-User %q, want %q", got, "oidc:alice@example.com")
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
