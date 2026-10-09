// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework"
	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework/helper"
)

const (
	clientID     = "kube-oidc-proxy"
	userPassword = "e2e-user-password"
	outsider     = "outsider"
	readersGroup = "k8s-readers"

	// teams is the number of directory groups besides the readers group, and
	// groupsPerUser the number each user holds, the readers group included.
	teams         = 50
	groupsPerUser = 5

	peopleDN = "ou=people,dc=example,dc=test"
	groupsDN = "ou=groups,dc=example,dc=test"
)

// The users the directory is loaded with, user0001 and on. The directory is
// passed to OpenLDAP in a ConfigMap, which caps it at about 1,800 users.
var users = envInt("KUBE_OIDC_PROXY_E2E_LDAP_USERS", 1000)

// The proxy's Kubernetes client limits. Its LDAP cache reads and writes
// ConfigMaps through this client, so they bound how fast new users and
// refresh cycles go; client-go's own defaults of 5 and 10 make a refresh of
// 1,000 users take over three minutes.
var (
	kubeClientQPS   = envInt("KUBE_OIDC_PROXY_E2E_KUBE_CLIENT_QPS", 50)
	kubeClientBurst = envInt("KUBE_OIDC_PROXY_E2E_KUBE_CLIENT_BURST", 100)
)

var _ = framework.CasesDescribe("LDAP group augmentation", func() {
	f := framework.NewBareFramework("ldap")

	It("takes groups from the directory and reports the latency it adds", func() {
		ns := f.Namespace.Name
		h := f.Helper()

		By(fmt.Sprintf("Deploying OpenLDAP with %d users in %d groups", users, teams+1))
		ldapBundle, ldapURL, err := h.DeployOpenLDAP(ns, directoryLDIF())
		Expect(err).NotTo(HaveOccurred())

		By("Deploying Keycloak, federating its users from the directory")
		keycloakBundle, keycloakURL, err := h.DeployKeycloak(ns, realmJSON(ldapURL.String()), ldapBundle.CertBytes)
		Expect(err).NotTo(HaveOccurred())
		issuerURL := keycloakURL.String() + "/realms/e2e"

		By("Allowing the " + readersGroup + " group to list pods")
		Expect(h.CreateRole(ns, "pod-reader", []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
		}, rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: "Group", Name: readersGroup})).To(Succeed())

		By("Deploying kube-oidc-proxy with LDAP group augmentation")
		proxyBundle, proxyURL, metricsURL, err := h.DeployLDAPProxy(f.Namespace, helper.LDAPProxyConfig{
			IssuerURL:  issuerURL,
			ClientID:   clientID,
			IssuerCA:   keycloakBundle.CertBytes,
			LDAPConfig: proxyLDAPConfig(ns, ldapURL.String()),
			LDAPCA:     ldapBundle.CertBytes,
			ExtraArgs: []string{
				"--kube-client-qps=" + strconv.Itoa(kubeClientQPS),
				"--kube-client-burst=" + strconv.Itoa(kubeClientBurst),
			},
		})
		Expect(err).NotTo(HaveOccurred())

		By("Logging users in to Keycloak and sending their requests through the proxy")
		logs, err := h.RunLDAPLoadgen(ns, []string{
			"--token-url=" + issuerURL + "/protocol/openid-connect/token",
			"--client-id=" + clientID,
			"--password=" + userPassword,
			"--outsider=" + outsider,
			"--users=" + strconv.Itoa(users),
			"--groups=" + strconv.Itoa(teams+1),
			"--groups-per-user=" + strconv.Itoa(groupsPerUser),
			"--ca-files=/ca/keycloak.pem,/ca/proxy.pem",
			"--proxy-url=" + proxyURL.String(),
			"--metrics-url=" + metricsURL.String(),
			"--namespace=" + ns,
			fmt.Sprintf("--proxy-kube-client=qps %d, burst %d", kubeClientQPS, kubeClientBurst),
		}, map[string][]byte{
			"keycloak.pem": keycloakBundle.CertBytes,
			"proxy.pem":    proxyBundle.CertBytes,
		}, 40*time.Minute)
		printReport(logs)
		Expect(err).NotTo(HaveOccurred(), logs)

		By("Checking a user's cached record holds their directory groups")
		name, err := cache.UserConfigMapName("user0001")
		Expect(err).NotTo(HaveOccurred())
		cm, err := f.KubeClientSet.CoreV1().ConfigMaps(ns).Get(context.TODO(), name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		var record cache.UserRecord
		Expect(yaml.Unmarshal([]byte(cm.Data[cache.UserRecordKey]), &record)).To(Succeed())
		Expect(record.Username).To(Equal("user0001"))
		Expect(record.Groups).To(ConsistOf(groupsOf(0)))
	})
})

// groupsOf returns the groups the user with the given index is in: the
// readers group and groupsPerUser-1 teams, spread so that every team is used.
func groupsOf(user int) []string {
	groups := []string{readersGroup}
	step := teams / (groupsPerUser - 1)
	for j := range groupsPerUser - 1 {
		groups = append(groups, fmt.Sprintf("team-%02d", (user+j*step)%teams+1))
	}
	return groups
}

func userName(i int) string { return fmt.Sprintf("user%04d", i+1) }

// directoryLDIF returns the directory: the users, the outsider, the readers
// group, the teams, and an outsiders group RBAC grants nothing.
func directoryLDIF() []byte {
	var b strings.Builder
	b.WriteString("dn: dc=example,dc=test\nobjectClass: dcObject\nobjectClass: organization\ndc: example\no: example\n\n")
	fmt.Fprintf(&b, "dn: %s\nobjectClass: organizationalUnit\nou: people\n\n", peopleDN)
	fmt.Fprintf(&b, "dn: %s\nobjectClass: organizationalUnit\nou: groups\n\n", groupsDN)

	members := map[string][]string{"outsiders": {outsider}}
	for i := range users {
		for _, g := range groupsOf(i) {
			members[g] = append(members[g], userName(i))
		}
	}

	for _, uid := range append([]string{outsider}, allUsers()...) {
		fmt.Fprintf(&b, "dn: uid=%[1]s,%[2]s\nobjectClass: inetOrgPerson\nuid: %[1]s\ncn: %[1]s\nsn: %[1]s\ngivenName: %[1]s\nmail: %[1]s@example.test\nuserPassword: %[3]s\n\n",
			uid, peopleDN, userPassword)
	}

	names := make([]string, 0, len(members))
	for g := range members {
		names = append(names, g)
	}
	slices.Sort(names)
	for _, g := range names {
		fmt.Fprintf(&b, "dn: cn=%[1]s,%[2]s\nobjectClass: groupOfNames\ncn: %[1]s\n", g, groupsDN)
		for _, uid := range members[g] {
			fmt.Fprintf(&b, "member: uid=%s,%s\n", uid, peopleDN)
		}
		b.WriteString("\n")
	}

	return []byte(b.String())
}

func allUsers() []string {
	out := make([]string, users)
	for i := range out {
		out[i] = userName(i)
	}
	return out
}

// realmJSON returns a realm whose users come from the directory, with a public
// client that may log in with a password, so that the test can get tokens
// without a browser.
func realmJSON(ldapURL string) []byte {
	one := func(v string) []string { return []string{v} }
	mapper := func(name, model, attr string) map[string]any {
		return map[string]any{
			"name":       name,
			"providerId": "user-attribute-ldap-mapper",
			"config": map[string][]string{
				"user.model.attribute":        one(model),
				"ldap.attribute":              one(attr),
				"read.only":                   one("true"),
				"always.read.value.from.ldap": one("false"),
				"is.mandatory.in.ldap":        one("true"),
			},
		}
	}

	realm := map[string]any{
		"realm":       "e2e",
		"enabled":     true,
		"sslRequired": "external",
		// Tokens must outlast the test: every user logs in before any of
		// them is sent through the proxy.
		"accessTokenLifespan": 3600,
		"requiredActions": []map[string]any{{
			"alias": "VERIFY_PROFILE", "name": "Verify Profile", "providerId": "VERIFY_PROFILE",
			"enabled": false, "defaultAction": false,
		}},
		"clients": []map[string]any{{
			"clientId":                  clientID,
			"enabled":                   true,
			"protocol":                  "openid-connect",
			"publicClient":              true,
			"standardFlowEnabled":       false,
			"directAccessGrantsEnabled": true,
		}},
		"components": map[string]any{
			"org.keycloak.storage.UserStorageProvider": []map[string]any{{
				"name":       "openldap",
				"providerId": "ldap",
				"config": map[string][]string{
					"enabled":               one("true"),
					"priority":              one("0"),
					"editMode":              one("READ_ONLY"),
					"importEnabled":         one("true"),
					"syncRegistrations":     one("false"),
					"vendor":                one("other"),
					"connectionUrl":         one(ldapURL),
					"authType":              one("simple"),
					"bindDn":                one(helper.LDAPBindDN),
					"bindCredential":        one(helper.LDAPBindPassword),
					"usersDn":               one(peopleDN),
					"usernameLDAPAttribute": one("uid"),
					"rdnLDAPAttribute":      one("uid"),
					"uuidLDAPAttribute":     one("entryUUID"),
					"userObjectClasses":     one("inetOrgPerson"),
					"searchScope":           one("1"),
					"pagination":            one("false"),
					"connectionPooling":     one("true"),
					"useTruststoreSpi":      one("always"),
					"trustEmail":            one("true"),
				},
				"subComponents": map[string]any{
					"org.keycloak.storage.ldap.mappers.LDAPStorageMapper": []map[string]any{
						mapper("username", "username", "uid"),
						mapper("first name", "firstName", "givenName"),
						mapper("last name", "lastName", "sn"),
						mapper("email", "email", "mail"),
					},
				},
			}},
		},
	}

	out, err := json.Marshal(realm)
	Expect(err).NotTo(HaveOccurred())
	return out
}

// proxyLDAPConfig returns the proxy's LDAP configuration. The refresh interval
// is short so that a full refresh can be measured within the test.
func proxyLDAPConfig(ns, ldapURL string) []byte {
	config := map[string]any{
		"backends": []map[string]any{{
			"name":               "openldap",
			"urls":               []string{ldapURL},
			"bindDN":             helper.LDAPBindDN,
			"bindPasswordFile":   "/ldap/bind-password",
			"caFile":             "/ldap/ca.pem",
			"userSearchBases":    []string{peopleDN},
			"userFilter":         "(objectClass=inetOrgPerson)",
			"usernameAttribute":  "uid",
			"groupSearchBases":   []string{groupsDN},
			"groupFilter":        "(objectClass=groupOfNames)",
			"groupNameAttribute": "cn",
		}},
		"cache":           map[string]string{"namespace": ns},
		"refreshInterval": "20s",
	}

	out, err := json.Marshal(config)
	Expect(err).NotTo(HaveOccurred())
	return out
}

// printReport prints the load generator's report, and writes it to
// $ARTIFACTS/ldap-latency-report.txt when ARTIFACTS is set.
func printReport(logs string) {
	start := strings.Index(logs, "===== LDAP latency report")
	if start < 0 {
		fmt.Println("ldap-loadgen produced no report")
		return
	}
	report := logs[start:]
	if end := strings.Index(report, "===== end of report ====="); end >= 0 {
		report = report[:end+len("===== end of report =====")]
	}

	fmt.Println(report)

	if dir := os.Getenv("ARTIFACTS"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err == nil {
			_ = os.WriteFile(filepath.Join(dir, "ldap-latency-report.txt"), []byte(report+"\n"), 0o644)
		}
	}
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}
