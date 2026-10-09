// Copyright Jetstack Ltd. See LICENSE for details.
package impersonation

import (
	"context"
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework"
)

var _ = framework.CasesDescribe("Impersonation", func() {
	f := framework.NewDefaultFramework("impersonation")

	It("should refuse impersonation headers even when the cluster's RBAC allows the impersonation", func() {
		// The test user may impersonate each of these through RBAC. The proxy
		// forwards with its own credentials, so it refuses the headers
		// outright rather than act on that grant.
		By("Impersonating as a user")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			UserName: "ok-to-impersonate@nodomain.dev",
		}, http.StatusForbidden, "impersonation headers are not accepted")

		By("Impersonating as a user and group")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			UserName: "ok-to-impersonate@nodomain.dev",
			Groups:   []string{"ok-to-impersonate-group"},
		}, http.StatusForbidden, "impersonation headers are not accepted")

		By("Impersonating as a user and extra")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			UserName: "ok-to-impersonate@nodomain.dev",
			Extra: map[string][]string{
				"oktoimpersonateextra": {"foo"},
			},
		}, http.StatusForbidden, "impersonation headers are not accepted")

		By("Impersonating as a group without a user")
		tryImpersonationClient(f, rest.ImpersonationConfig{
			Groups: []string{"system:masters"},
		}, http.StatusForbidden, "impersonation headers are not accepted")
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
