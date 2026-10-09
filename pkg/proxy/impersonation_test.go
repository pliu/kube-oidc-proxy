// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/reqctx"
)

// A request may never act as somebody else, whether groups come from the token
// or from the directory. The proxy forwards with credentials that may
// impersonate anyone, so honouring the headers would let any authenticated
// user choose who they run as.
func TestImpersonationHeadersAreRefused(t *testing.T) {
	headers := map[string]http.Header{
		"a user":                  {"Impersonate-User": {"jjackson"}},
		"a user and group":        {"Impersonate-User": {"jjackson"}, "Impersonate-Group": {"group3"}},
		"a group without a user":  {"Impersonate-Group": {"system:masters"}},
		"a uid":                   {"Impersonate-User": {"jjackson"}, "Impersonate-Uid": {"1-2-3-4"}},
		"an extra":                {"Impersonate-User": {"jjackson"}, "Impersonate-Extra-Scopes": {"view"}},
		"an unknown header":       {"Impersonate-Not-Real": {"bar"}},
		"a lower case header key": {"impersonate-user": {"jjackson"}},
	}

	for _, ldap := range []bool{false, true} {
		for name, header := range headers {
			t.Run(map[bool]string{false: "token groups/", true: "ldap groups/"}[ldap]+name, func(t *testing.T) {
				p := newTestProxy(t)
				defer p.ctrl.Finish()

				augmenter := &fakeAugmenter{mapping: map[string][]string{"alice@example.net": {"admins"}}}
				if ldap {
					p.ldapDirectory = augmenter
				}

				req := newLDAPRequest("/api/v1/pods", http.MethodGet)
				for k, vs := range header {
					req.Header[k] = vs
				}

				p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
					&authenticator.Response{User: &user.DefaultInfo{Name: "alice@example.net"}}, true, nil)

				var proxied bool
				handler := p.withHandlers(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					proxied = true
				}))

				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				if code := w.Result().StatusCode; code != http.StatusForbidden {
					t.Errorf("got unexpected response code, exp=%d got=%d", http.StatusForbidden, code)
				}

				// The refusal has to say why, or it reads as an RBAC decision
				// the caller could go and get themselves granted.
				if body := w.Body.String(); !strings.Contains(body, errImpersonationNotAccepted.Error()) {
					t.Errorf("expected the response to explain the refusal, got %q", body)
				}

				if proxied {
					t.Error("expected the request never to reach the API server")
				}

				// Refused before the directory is asked, so a request that is
				// going to be turned away costs no lookup.
				if augmenter.resolveCount != 0 {
					t.Errorf("expected no LDAP lookup, got %d", augmenter.resolveCount)
				}
			})
		}
	}
}

// headerRecorder records the headers of the request that reaches the API
// server.
type headerRecorder struct {
	header http.Header
}

func (h *headerRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	h.header = req.Header.Clone()
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// The request handed to the transports must not carry anything from the client
// that speaks for its identity, even if a header got past the handlers. Left
// in, the impersonating transport would forward the client's Impersonate-User
// in place of the identity built for the request, and the bearer transport
// would forward the client's Authorization in place of the proxy's.
func TestRoundTripForwardsOnlyTheBuiltIdentity(t *testing.T) {
	recorder := &headerRecorder{}
	p := &Proxy{clientTransport: recorder}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	req.Header = http.Header{
		"Impersonate-User":         {"admin"},
		"Impersonate-Group":        {"system:masters"},
		"Impersonate-Extra-Scopes": {"all"},
		"impersonate-uid":          {"0"},
		"Authorization":            {"Bearer client-token"},
		"authorization":            {"Bearer other-client-token"},
		"Accept":                   {"application/json"},
	}
	original := req.Header.Clone()

	requester := &user.DefaultInfo{Name: "alice", Groups: []string{"developers"}}
	req = reqctx.WithImpersonationConfig(req, buildImpersonation(requester, "192.0.2.1", &Config{}))

	if _, err := p.RoundTrip(req); err != nil {
		t.Fatal(err)
	}

	got := recorder.header
	if user := got.Values("Impersonate-User"); len(user) != 1 || user[0] != "alice" {
		t.Errorf("expected to impersonate only alice, got %q", user)
	}
	if groups := got.Values("Impersonate-Group"); strings.Join(groups, ",") != "developers,"+user.AllAuthenticated {
		t.Errorf("unexpected impersonated groups: %q", groups)
	}
	for name := range got {
		if strings.HasPrefix(strings.ToLower(name), "impersonate-extra-") || strings.EqualFold(name, "impersonate-uid") {
			t.Errorf("client header %q reached the API server", name)
		}
	}
	for name, values := range got {
		if strings.EqualFold(name, "Authorization") {
			t.Errorf("client Authorization reached the API server: %q", values)
		}
	}
	if got.Get("Accept") != "application/json" {
		t.Error("expected unrelated headers to be forwarded")
	}

	// A round tripper must not modify the request it is given.
	if !headersEqual(req.Header, original) {
		t.Errorf("request headers were modified: %v", req.Header)
	}
}

func headersEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, vs := range a {
		if strings.Join(vs, "\x00") != strings.Join(b[k], "\x00") {
			return false
		}
	}
	return true
}
