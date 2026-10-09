// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/jetstack/kube-oidc-proxy/test/kind"
	"github.com/jetstack/kube-oidc-proxy/test/util"
)

const (
	// LDAPBindDN and LDAPBindPassword are the directory's root credentials,
	// set in test/tools/openldap/slapd.conf.
	LDAPBindDN       = "cn=admin,dc=example,dc=test"
	LDAPBindPassword = "e2e-ldap-password"

	keycloakName = "keycloak-e2e"
	ldapName     = "openldap-e2e"
)

// DeployOpenLDAP deploys OpenLDAP serving LDAPS, loaded with the given LDIF,
// and returns the key bundle it serves with.
func (h *Helper) DeployOpenLDAP(ns string, ldif []byte) (*util.KeyBundle, *url.URL, error) {
	cm, err := h.KubeClient.CoreV1().ConfigMaps(ns).Create(context.TODO(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "openldap-data-", Namespace: ns},
		Data:       map[string]string{"directory.ldif": string(ldif)},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	cnt := corev1.Container{
		Name:            ldapName,
		Image:           kind.OpenLDAPImageName,
		ImagePullPolicy: corev1.PullNever,
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/tls", Name: "tls", ReadOnly: true},
			{MountPath: "/data", Name: "data", ReadOnly: true},
		},
		Ports: []corev1.ContainerPort{{ContainerPort: 6443}},
		// Ready once the directory is loaded, not merely listening.
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{Command: []string{"test", "-f", "/run/slapd/loaded"}},
			},
			PeriodSeconds: 1,
		},
	}

	data := corev1.Volume{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: cm.Name},
			},
		},
	}

	bundle, appURL, err := h.deployAppWithTimeout(ns, ldapName, corev1.ServiceTypeClusterIP, 3*time.Minute, cnt, data)
	if err != nil {
		return nil, nil, err
	}

	appURL.Scheme = "ldaps"
	return bundle, appURL, nil
}

// DeployKeycloak deploys Keycloak serving HTTPS with realmJSON imported. The
// realm's LDAP federation is verified against ldapCA. It returns the key
// bundle Keycloak serves with and its base URL, which is also the base of the
// issuer of the realm's tokens.
func (h *Helper) DeployKeycloak(ns string, realmJSON []byte, ldapCA []byte) (*util.KeyBundle, *url.URL, error) {
	realm, err := h.KubeClient.CoreV1().ConfigMaps(ns).Create(context.TODO(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "keycloak-realm-", Namespace: ns},
		Data:       map[string]string{"realm.json": string(realmJSON)},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	trust, err := h.KubeClient.CoreV1().ConfigMaps(ns).Create(context.TODO(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "keycloak-ldap-ca-", Namespace: ns},
		Data:       map[string]string{"ldap-ca.pem": string(ldapCA)},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	_, base := h.appURL(ns, keycloakName, "6443")
	cnt := corev1.Container{
		Name:            keycloakName,
		Image:           kind.KeycloakImage,
		ImagePullPolicy: corev1.PullNever,
		Args: []string{
			"start-dev",
			"--import-realm",
			"--hostname=" + base,
			"--http-enabled=false",
			"--https-port=6443",
			"--https-certificate-file=/tls/cert.pem",
			"--https-certificate-key-file=/tls/key.pem",
			"--truststore-paths=/ldap-ca/ldap-ca.pem",
			"--health-enabled=true",
		},
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/tls", Name: "tls", ReadOnly: true},
			{MountPath: "/opt/keycloak/data/import", Name: "realm", ReadOnly: true},
			{MountPath: "/ldap-ca", Name: "ldap-ca", ReadOnly: true},
		},
		Ports: []corev1.ContainerPort{{ContainerPort: 6443}, {ContainerPort: 9000}},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/health/ready",
					Port:   intstr.FromInt(9000),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			PeriodSeconds: 2,
		},
	}

	volumes := []corev1.Volume{
		{
			Name: "realm",
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: realm.Name},
			}},
		},
		{
			Name: "ldap-ca",
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: trust.Name},
			}},
		},
	}

	return h.deployAppWithTimeout(ns, keycloakName, corev1.ServiceTypeClusterIP, 5*time.Minute, cnt, volumes...)
}

// LDAPProxyConfig is what DeployLDAPProxy runs the proxy with.
type LDAPProxyConfig struct {
	IssuerURL  string
	ClientID   string
	IssuerCA   []byte
	LDAPConfig []byte // the --ldap-config-file document
	LDAPCA     []byte // mounted at /ldap/ca.pem
	ExtraArgs  []string
}

// DeployLDAPProxy deploys the proxy with LDAP group augmentation, taking the
// username from preferred_username. Alongside the proxy's own Service it
// creates <name>-metrics for the metrics on the probe port.
func (h *Helper) DeployLDAPProxy(ns *corev1.Namespace, config LDAPProxyConfig) (*util.KeyBundle, *url.URL, *url.URL, error) {
	authn := fmt.Sprintf(`issuers:
- issuer:
    url: %s
    audiences: [%s]
    certificateAuthority: |
      %s
  claimMappings:
    username:
      claim: preferred_username
      prefix: ""
`, config.IssuerURL, config.ClientID,
		strings.ReplaceAll(strings.TrimSpace(string(config.IssuerCA)), "\n", "\n      "))

	if _, err := h.KubeClient.CoreV1().Secrets(ns.Name).Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-config", Namespace: ns.Name},
		Data: map[string][]byte{
			"authn.yaml": []byte(authn),
		},
	}, metav1.CreateOptions{}); err != nil {
		return nil, nil, nil, err
	}

	if _, err := h.KubeClient.CoreV1().Secrets(ns.Name).Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ldap-config", Namespace: ns.Name},
		Data: map[string][]byte{
			"ldap.json":     config.LDAPConfig,
			"ca.pem":        config.LDAPCA,
			"bind-password": []byte(LDAPBindPassword),
		},
	}, metav1.CreateOptions{}); err != nil {
		return nil, nil, nil, err
	}

	cnt := corev1.Container{
		Name:            kind.ProxyImageName,
		Image:           kind.ProxyImageName,
		ImagePullPolicy: corev1.PullNever,
		Args: append([]string{
			"kube-oidc-proxy",
			"--secure-port=6443",
			"--tls-cert-file=/tls/cert.pem",
			"--tls-private-key-file=/tls/key.pem",
			"--oidc-config-file=/oidc/authn.yaml",
			"--ldap-config-file=/ldap/ldap.json",
			// Quiet enough that logging does not weigh on the latency measured.
			"--v=1",
		}, config.ExtraArgs...),
		VolumeMounts: []corev1.VolumeMount{
			{MountPath: "/tls", Name: "tls", ReadOnly: true},
			{MountPath: "/oidc", Name: "oidc", ReadOnly: true},
			{MountPath: "/ldap", Name: "ldap", ReadOnly: true},
		},
		Ports: []corev1.ContainerPort{{ContainerPort: 6443}, {ContainerPort: 8080}},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromInt(8080)},
			},
			PeriodSeconds: 2,
		},
	}

	volumes := []corev1.Volume{
		{Name: "oidc", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "oidc-config"}}},
		{Name: "ldap", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "ldap-config"}}},
	}

	if err := h.grantLDAPProxy(ns); err != nil {
		return nil, nil, nil, err
	}

	bundle, appURL, err := h.deployAppWithTimeout(ns.Name, kind.ProxyImageName, corev1.ServiceTypeClusterIP, 2*time.Minute, cnt, volumes...)
	if err != nil {
		return nil, nil, nil, err
	}

	metricsName := kind.ProxyImageName + "-metrics"
	if _, err := h.KubeClient.CoreV1().Services(ns.Name).Create(context.TODO(), &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: metricsName, Namespace: ns.Name},
		Spec: corev1.ServiceSpec{
			Ports:    []corev1.ServicePort{{Port: 8080, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt(8080)}},
			Selector: map[string]string{"app": kind.ProxyImageName},
		},
	}, metav1.CreateOptions{}); err != nil {
		return nil, nil, nil, err
	}

	metricsURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("%s.%s.svc.cluster.local:8080", metricsName, ns.Name), Path: "/metrics"}
	return bundle, appURL, metricsURL, nil
}

// grantLDAPProxy lets the proxy impersonate, elect a leader and keep its
// LDAP cache in the namespace.
func (h *Helper) grantLDAPProxy(ns *corev1.Namespace) error {
	subject := rbacv1.Subject{Kind: "ServiceAccount", Name: kind.ProxyImageName, Namespace: ns.Name}

	impersonate, err := h.KubeClient.RbacV1().ClusterRoles().Create(context.TODO(), &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{GenerateName: kind.ProxyImageName + "-ldap-", OwnerReferences: namespaceOwner(ns)},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups"},
				Verbs:     []string{"impersonate"},
			},
			{
				// The OIDC authenticator records a token's jti as this extra,
				// which the proxy forwards with the rest of the identity.
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"userextras/authentication.kubernetes.io/credential-id"},
				Verbs:     []string{"impersonate"},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if _, err := h.KubeClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{GenerateName: kind.ProxyImageName + "-ldap-", OwnerReferences: namespaceOwner(ns)},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: impersonate.Name},
		Subjects:   []rbacv1.Subject{subject},
	}, metav1.CreateOptions{}); err != nil {
		return err
	}

	return h.CreateRole(ns.Name, kind.ProxyImageName+"-ldap", []rbacv1.PolicyRule{
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"create", "get", "update"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list", "watch", "create", "update"}},
	}, subject)
}

// CreateRole creates a Role with the given rules, bound to subjects.
func (h *Helper) CreateRole(ns, name string, rules []rbacv1.PolicyRule, subjects ...rbacv1.Subject) error {
	if _, err := h.KubeClient.RbacV1().Roles(ns).Create(context.TODO(), &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Rules:      rules,
	}, metav1.CreateOptions{}); err != nil {
		return err
	}

	_, err := h.KubeClient.RbacV1().RoleBindings(ns).Create(context.TODO(), &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name},
		Subjects:   subjects,
	}, metav1.CreateOptions{})
	return err
}

// RunLDAPLoadgen runs ldap-loadgen as a Job with the given arguments and CA
// bundles mounted at /ca/<key>, waits for it to finish and returns its log.
// The error is set if it failed or did not finish within timeout.
func (h *Helper) RunLDAPLoadgen(ns string, args []string, cas map[string][]byte, timeout time.Duration) (string, error) {
	const name = "ldap-loadgen"

	caData := map[string]string{}
	for k, v := range cas {
		caData[k] = string(v)
	}
	if _, err := h.KubeClient.CoreV1().ConfigMaps(ns).Create(context.TODO(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-ca", Namespace: ns},
		Data:       caData,
	}, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	if _, err := h.KubeClient.CoreV1().ServiceAccounts(ns).Create(context.TODO(), &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	// Its direct requests to the API server list pods, as its users do.
	if err := h.CreateRole(ns, name, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
	}, rbacv1.Subject{Kind: "ServiceAccount", Name: name, Namespace: ns}); err != nil {
		return "", err
	}

	backoff := int32(0)
	job, err := h.KubeClient.BatchV1().Jobs(ns).Create(context.TODO(), &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoff,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					ServiceAccountName: name,
					RestartPolicy:      corev1.RestartPolicyNever,
					Containers: []corev1.Container{{
						Name:            name,
						Image:           kind.LDAPLoadgenImageName,
						ImagePullPolicy: corev1.PullNever,
						Args:            args,
						VolumeMounts:    []corev1.VolumeMount{{MountPath: "/ca", Name: "ca", ReadOnly: true}},
					}},
					Volumes: []corev1.Volume{{
						Name: "ca",
						VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: name + "-ca"},
						}},
					}},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}

	var failed bool
	waitErr := wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		j, err := h.KubeClient.BatchV1().Jobs(ns).Get(ctx, job.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, c := range j.Status.Conditions {
			if c.Status != corev1.ConditionTrue {
				continue
			}
			switch c.Type {
			case batchv1.JobComplete:
				return true, nil
			case batchv1.JobFailed:
				failed = true
				return true, nil
			}
		}
		return false, nil
	})

	logs, logErr := h.jobLogs(ns, name)
	switch {
	case waitErr != nil:
		return logs, fmt.Errorf("ldap-loadgen did not finish: %w", waitErr)
	case failed:
		return logs, fmt.Errorf("ldap-loadgen failed")
	case logErr != nil:
		return logs, logErr
	}
	return logs, nil
}

func (h *Helper) jobLogs(ns, app string) (string, error) {
	pods, err := h.KubeClient.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{LabelSelector: "app=" + app})
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, pod := range pods.Items {
		raw, err := h.KubeClient.CoreV1().Pods(ns).GetLogs(pod.Name, &corev1.PodLogOptions{}).DoRaw(context.TODO())
		if err != nil {
			return out.String(), err
		}
		out.Write(raw)
	}
	return out.String(), nil
}

func namespaceOwner(ns *corev1.Namespace) []metav1.OwnerReference {
	pTrue, pFalse := true, false
	return []metav1.OwnerReference{{
		APIVersion:         "v1",
		Kind:               "Namespace",
		Name:               ns.Name,
		UID:                ns.UID,
		BlockOwnerDeletion: &pTrue,
		Controller:         &pFalse,
	}}
}
