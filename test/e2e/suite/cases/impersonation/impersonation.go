// Copyright Jetstack Ltd. See LICENSE for details.
package impersonation

import (
	"context"
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework"
)

var _ = framework.CasesDescribe("Impersonation", func() {
	f := framework.NewDefaultFramework("impersonation")

	It("should allow an authenticated user to impersonate an authorized user when az by rbac", func() {

		By("Creating ClusterRole for user ok-to-impersonate@nodomain.dev to list Pods")
		rolePods, err := f.Helper().KubeClient.RbacV1().ClusterRoles().Create(context.TODO(), &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-user-role-pods-impersonate-",
			},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating ClusterRoleBinding for user ok-to-impersonate@nodomain.dev")
		_, err = f.Helper().KubeClient.RbacV1().ClusterRoleBindings().Create(context.TODO(),
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-user-binding-impersonate",
				},
				Subjects: []rbacv1.Subject{{Name: "ok-to-impersonate@nodomain.dev", Kind: "User"}},
				RoleRef:  rbacv1.RoleRef{Name: rolePods.Name, Kind: "ClusterRole"},
			}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Impersonating a user, group, and extra")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			UserName: "ok-to-impersonate@nodomain.dev",
			Groups: []string{
				"ok-to-impersonate-group",
			},
			Extra: map[string][]string{
				"oktoimpersonateextra": {
					"foo",
				},
			},
		}, http.StatusOK, "")

	})

	It("should error at proxy when impersonation enabled but a user is not specified", func() {
		By("Impersonating as a group")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			Groups: []string{
				"group-1",
				"group-2",
			},
		}, http.StatusBadRequest, "no Impersonation-User header found for request")

		By("Impersonating as a extra")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			Extra: map[string][]string{
				"foo": {
					"k1", "k2", "k3",
				},
				"bar": {
					"k1", "k2", "k3",
				},
			},
		}, http.StatusBadRequest, "no Impersonation-User header found for request")
	})

	It("should return error from proxy when impersonation enabled and impersonation is not authorized by the cluster's RBAC", func() {
		By("Impersonating as a user")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			UserName: "foo@example.com",
		}, http.StatusForbidden, "user@example.com is not allowed to impersonate user 'foo@example.com'")

		By("Impersonating as a user, group")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			UserName: "ok-to-impersonate@nodomain.dev",
			Groups: []string{
				"group-1",
			},
		}, http.StatusForbidden, "user@example.com is not allowed to impersonate group 'group-1'")

		By("Impersonating as a user, extra")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			UserName: "ok-to-impersonate@nodomain.dev",
			Extra: map[string][]string{
				"foo": {
					"k1", "k2", "k3",
				},
			},
		}, http.StatusForbidden, "user@example.com is not allowed to impersonate extra info 'foo'='k1'")

	})

	It("should forward the request with the caller's own token when impersonation is disabled", func() {
		By("Enabling the disabling of impersonation")
		f.DeployProxyWith(nil, "--disable-impersonation")

		// The proxy accepts the token and forwards the request as it is,
		// impersonation headers included. The API server is not configured to
		// trust the e2e issuer, so it rejecting that token is what shows the
		// token reached it - a request forwarded without one would instead
		// have been served as system:anonymous.
		config := f.NewProxyRestConfig()
		config.Impersonate = rest.ImpersonationConfig{
			UserName: "foo@example.com",
		}
		client, err := kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred())

		_, err = client.CoreV1().Pods(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
		Expect(err).To(HaveOccurred())

		kErr, ok := err.(*k8sErrors.StatusError)
		Expect(ok).To(BeTrue(), "expected a status error, got %v", err)
		Expect(kErr.ErrStatus.Code).To(BeEquivalentTo(http.StatusUnauthorized))

		// The proxy answers a token it rejects with a plain text body, which
		// client-go reports with a message of its own. Only the API server
		// answers with a Status of its own.
		Expect(kErr.ErrStatus.Message).To(Equal("Unauthorized"))
	})
})

func tryImpersonationClient(f *framework.Framework, impConfig rest.ImpersonationConfig, expectedCode int, expRespBody string) {
	// build client with impersonation
	config := f.NewProxyRestConfig()
	config.Impersonate = impConfig
	client, err := kubernetes.NewForConfig(config)
	Expect(err).NotTo(HaveOccurred())

	var resp string
	var respCode int

	_, err = client.CoreV1().Pods(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		kErr, ok := err.(*k8sErrors.StatusError)
		if !ok {
			Expect(err).NotTo(HaveOccurred())
		}
		respCode = int(kErr.ErrStatus.Code)
		fmt.Printf("http status code %d\n", respCode)
		if respCode != http.StatusOK {
			if len(kErr.Status().Details.Causes) > 0 {
				resp = kErr.Status().Details.Causes[0].Message
			} else {
				resp = kErr.Error()
			}
		} else {
			resp = ""
		}

	} else {
		respCode = http.StatusOK
	}

	// check body and status code the token was rejected
	//if int(kErr.Status().Code) != http.StatusForbidden ||

	if respCode != expectedCode {
		Expect(fmt.Errorf("expected status code=%d, got=%d resp=%s", expectedCode, respCode, resp)).NotTo(HaveOccurred())
	}

	if resp != expRespBody {
		Expect(fmt.Errorf("expected response=%s, got=%s", expRespBody, resp)).NotTo(HaveOccurred())
	}

	/*if int(kErr.Status().Code) != expectedCode ||
		resp != expRespBody {
		Expect(fmt.Errorf("expected status code %d with body \"%s\", got code=%d, body=\"%s\"",
			http.StatusForbidden, expRespBody, int(kErr.Status().Code), resp)).NotTo(HaveOccurred())
	}*/
}
