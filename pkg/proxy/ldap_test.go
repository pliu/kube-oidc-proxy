// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	gocontext "context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	azv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	fakesubjectaccessreview "github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
)

// fakeAugmenter stands in for a live LDAP backend.
type fakeAugmenter struct {
	mapping map[string][]string

	// refreshUsers is the set of users allowed to trigger a refresh. Empty
	// allows everyone, as the real directory does.
	refreshUsers []string

	refreshErr   error
	refreshCount int

	refreshEndpointDisabled bool

	// directory is what a search for one user finds, standing in for the
	// directories being searched for somebody the mapping does not hold.
	directory map[string][]string

	directoryErr error
	userRefresh  []string
}

func (f *fakeAugmenter) RefreshEndpointEnabled() bool { return !f.refreshEndpointDisabled }

func (f *fakeAugmenter) CanRefresh(username string) bool {
	if len(f.refreshUsers) == 0 {
		return true
	}

	for _, allowed := range f.refreshUsers {
		if allowed == username {
			return true
		}
	}

	return false
}

func (f *fakeAugmenter) Groups(username string) ([]string, bool) {
	groups, ok := f.mapping[username]
	return groups, ok
}

func (f *fakeAugmenter) RefreshUser(_ gocontext.Context, username string) (*ldap.UserStats, error) {
	f.userRefresh = append(f.userRefresh, username)

	if f.directoryErr != nil {
		return nil, f.directoryErr
	}

	groups, found := f.directory[username]

	return &ldap.UserStats{
		User:    username,
		Found:   found,
		Groups:  len(groups),
		Changed: found,
	}, nil
}

func (f *fakeAugmenter) Run(stopCh <-chan struct{}) error { return nil }

func (f *fakeAugmenter) Refresh() error {
	f.refreshCount++
	return f.refreshErr
}

func (f *fakeAugmenter) Stats() *ldap.Stats {
	return &ldap.Stats{Users: len(f.mapping)}
}

// serveWithAD runs a request that authenticates as tokenUser through the full
// handler chain, with the given directory in place.
func serveWithAD(t *testing.T, p *fakeProxy, req *http.Request, tokenUser user.Info) *http.Response {
	t.Helper()

	if tokenUser != nil {
		p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
			&authenticator.Response{User: tokenUser}, true, nil)
	}

	handler := p.withHandlers(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, err := p.RoundTrip(req); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w.Result()
}

func newADRequest(path string, method string) *http.Request {
	u := new(url.URL)
	u.Path = path

	return &http.Request{
		Method: method,
		URL:    u,
		Header: http.Header{"Authorization": []string{"bearer fake-token"}},
	}
}

func TestAugmentedGroupsAreImpersonated(t *testing.T) {
	tests := map[string]struct {
		mapping map[string][]string

		tokenUser *user.DefaultInfo
		expGroup  []string
	}{
		"directory groups replace the groups of the token": {
			mapping:   map[string][]string{"alice@example.net": {"admins", "devs"}},
			tokenUser: &user.DefaultInfo{Name: "alice@example.net", Groups: []string{"from-token"}},
			expGroup:  []string{"admins", "devs", user.AllAuthenticated},
		},
		"a known user in no directory groups keeps none of their token groups": {
			mapping:   map[string][]string{"alice@example.net": {}},
			tokenUser: &user.DefaultInfo{Name: "alice@example.net", Groups: []string{"from-token"}},
			expGroup:  []string{user.AllAuthenticated},
		},
		// There is no fallback to the groups of the token. A user the
		// directories do not hold can do only what system:authenticated
		// allows, however many groups their token claims.
		"a user in no directory is given no groups": {
			mapping:   map[string][]string{"bob@example.net": {"admins"}},
			tokenUser: &user.DefaultInfo{Name: "alice@example.net", Groups: []string{"from-token"}},
			expGroup:  []string{user.AllAuthenticated},
		},
		"a user in no directory keeps none of the groups their token claims": {
			mapping:   map[string][]string{"bob@example.net": {"admins"}},
			tokenUser: &user.DefaultInfo{Name: "alice@example.net", Groups: []string{"cluster-admins", "from-token"}},
			expGroup:  []string{user.AllAuthenticated},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			defer p.ctrl.Finish()

			p.ldapDirectory = &fakeAugmenter{mapping: test.mapping}

			p.fakeRT.expUser = test.tokenUser.GetName()
			p.fakeRT.expGroup = test.expGroup

			resp := serveWithAD(t, p, newADRequest("/api/v1/pods", http.MethodGet), test.tokenUser)

			if resp.StatusCode != http.StatusOK {
				t.Errorf("got unexpected response code, exp=%d got=%d",
					http.StatusOK, resp.StatusCode)
			}
		})
	}
}

// With no directory configured the groups of the token must be used as before.
func TestGroupsUnchangedWhenLDAPDisabled(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	p.fakeRT.expUser = "alice@example.net"
	p.fakeRT.expGroup = []string{"from-token", user.AllAuthenticated}

	resp := serveWithAD(t, p, newADRequest("/api/v1/pods", http.MethodGet),
		&user.DefaultInfo{Name: "alice@example.net", Groups: []string{"from-token"}})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusOK, resp.StatusCode)
	}
}

func TestLDAPRefreshEndpoint(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	directory := &fakeAugmenter{mapping: map[string][]string{"alice@example.net": {"admins"}}}
	p.ldapDirectory = directory

	resp := serveWithAD(t, p, newADRequest(LDAPRefreshPath, http.MethodPost),
		&user.DefaultInfo{Name: "alice@example.net"})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got unexpected response code, exp=%d got=%d", http.StatusOK, resp.StatusCode)
	}

	if directory.refreshCount != 1 {
		t.Errorf("expected exactly one refresh, got %d", directory.refreshCount)
	}

	var stats ldap.Stats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode response: %s", err)
	}

	if stats.Users != 1 {
		t.Errorf("expected stats of 1 user, got %d", stats.Users)
	}
}

// Refreshing one user searches the directories for them alone rather than
// sweeping the whole of every one, which is what makes a change to a single
// user cheap enough to ask for as soon as it is made.
func TestLDAPRefreshEndpointRefreshesOneUser(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	directory := &fakeAugmenter{
		mapping:   map[string][]string{"alice@example.net": {"admins"}},
		directory: map[string][]string{"bob@example.net": {"devs", "admins"}},
	}
	p.ldapDirectory = directory

	req := newADRequest(LDAPRefreshPath, http.MethodPost)
	req.URL.RawQuery = url.Values{LDAPRefreshUserParam: {"bob@example.net"}}.Encode()

	resp := serveWithAD(t, p, req, &user.DefaultInfo{Name: "alice@example.net"})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got unexpected response code, exp=%d got=%d", http.StatusOK, resp.StatusCode)
	}

	if exp := []string{"bob@example.net"}; !reflect.DeepEqual(directory.userRefresh, exp) {
		t.Errorf("expected the named user to have been refreshed, exp=%v got=%v",
			exp, directory.userRefresh)
	}

	// Everybody else is left alone: the whole point is not rebuilding them.
	if directory.refreshCount != 0 {
		t.Errorf("expected no rebuild of the whole mapping, got %d", directory.refreshCount)
	}

	var stats ldap.UserStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode response: %s", err)
	}

	if !stats.Found || !stats.Changed || stats.Groups != 2 {
		t.Errorf("unexpected stats: %+v", stats)
	}

	// How many groups they hold, not which: by default any authenticated user
	// may call this, and naming them would make it a way of reading the group
	// membership of anybody whose username can be guessed.
	if stats.User != "bob@example.net" {
		t.Errorf("expected the refreshed user to be named, got %q", stats.User)
	}
}

func TestLDAPRefreshEndpointReportsAFailedUserRefresh(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	directory := &fakeAugmenter{
		mapping:      map[string][]string{"alice@example.net": {"admins"}},
		directoryErr: errors.New("directory is unreachable"),
	}
	p.ldapDirectory = directory

	req := newADRequest(LDAPRefreshPath, http.MethodPost)
	req.URL.RawQuery = url.Values{LDAPRefreshUserParam: {"bob@example.net"}}.Encode()

	resp := serveWithAD(t, p, req, &user.DefaultInfo{Name: "alice@example.net"})

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusInternalServerError, resp.StatusCode)
	}
}

func TestLDAPReaderDoesNotServeRefreshEndpoint(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	directory := &fakeAugmenter{
		mapping:                 map[string][]string{"alice@example.net": {"admins"}},
		refreshEndpointDisabled: true,
	}
	p.ldapDirectory = directory

	// A reader treats the path like any other request and sends it to the API
	// server with the groups from the mapping it serves.
	p.fakeRT.expUser = "alice@example.net"
	p.fakeRT.expGroup = []string{"admins", user.AllAuthenticated}

	resp := serveWithAD(t, p, newADRequest(LDAPRefreshPath, http.MethodPost),
		&user.DefaultInfo{Name: "alice@example.net"})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got unexpected response code, exp=%d got=%d", http.StatusOK, resp.StatusCode)
	}
	if directory.refreshCount != 0 {
		t.Errorf("expected the reader not to refresh, got %d refreshes", directory.refreshCount)
	}
}

func TestLDAPRefreshEndpointAllowedUsers(t *testing.T) {
	tests := map[string]struct {
		refreshUsers []string
		requester    string

		expCode      int
		expRefreshes int
	}{
		"any authenticated user may refresh when no users are configured": {
			refreshUsers: nil,
			requester:    "alice@example.net",
			expCode:      http.StatusOK,
			expRefreshes: 1,
		},
		"an allowed user may refresh": {
			refreshUsers: []string{"alice@example.net", "bob@example.net"},
			requester:    "bob@example.net",
			expCode:      http.StatusOK,
			expRefreshes: 1,
		},
		"a user not in the allowed users is forbidden": {
			refreshUsers: []string{"alice@example.net"},
			requester:    "eve@example.net",
			expCode:      http.StatusForbidden,
			expRefreshes: 0,
		},
		"a user not in a single entry allowed list is forbidden": {
			refreshUsers: []string{"alice@example.net"},
			requester:    "alice@example.net.evil",
			expCode:      http.StatusForbidden,
			expRefreshes: 0,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			defer p.ctrl.Finish()

			directory := &fakeAugmenter{refreshUsers: test.refreshUsers}
			p.ldapDirectory = directory

			resp := serveWithAD(t, p, newADRequest(LDAPRefreshPath, http.MethodPost),
				&user.DefaultInfo{Name: test.requester})

			if resp.StatusCode != test.expCode {
				t.Errorf("got unexpected response code, exp=%d got=%d",
					test.expCode, resp.StatusCode)
			}

			if directory.refreshCount != test.expRefreshes {
				t.Errorf("expected %d refreshes, got %d",
					test.expRefreshes, directory.refreshCount)
			}
		})
	}
}

// The endpoint sits behind authentication, so an unauthenticated request must
// not be able to trigger a refresh.
func TestLDAPRefreshEndpointRequiresAuthentication(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	directory := &fakeAugmenter{}
	p.ldapDirectory = directory

	req := newADRequest(LDAPRefreshPath, http.MethodPost)
	req.Header = http.Header{}

	resp := serveWithAD(t, p, req, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusUnauthorized, resp.StatusCode)
	}

	if directory.refreshCount != 0 {
		t.Errorf("expected no refresh, got %d", directory.refreshCount)
	}
}

func TestLDAPRefreshEndpointRejectsGET(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	directory := &fakeAugmenter{}
	p.ldapDirectory = directory

	resp := serveWithAD(t, p, newADRequest(LDAPRefreshPath, http.MethodGet),
		&user.DefaultInfo{Name: "alice@example.net"})

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusMethodNotAllowed, resp.StatusCode)
	}

	if directory.refreshCount != 0 {
		t.Errorf("expected no refresh, got %d", directory.refreshCount)
	}
}

func TestLDAPRefreshEndpointReportsFailure(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	p.ldapDirectory = &fakeAugmenter{refreshErr: errors.New("directory is down")}

	resp := serveWithAD(t, p, newADRequest(LDAPRefreshPath, http.MethodPost),
		&user.DefaultInfo{Name: "alice@example.net"})

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusInternalServerError, resp.StatusCode)
	}
}

// The refresh path is not a valid API server path, but a request to a path
// that merely looks like it must still be proxied.
func TestLDAPRefreshPathIsNotProxied(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	p.ldapDirectory = &fakeAugmenter{mapping: map[string][]string{"alice@example.net": {"admins"}}}

	p.fakeRT.expUser = "alice@example.net"
	p.fakeRT.expGroup = []string{"admins", user.AllAuthenticated}

	resp := serveWithAD(t, p, newADRequest(LDAPRefreshPath+"/subpath", http.MethodPost),
		&user.DefaultInfo{Name: "alice@example.net"})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusOK, resp.StatusCode)
	}
}

// Guard the assumption the fakeRT comparison relies on.
func TestAugmentGroupsPreservesIdentity(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	p.ldapDirectory = &fakeAugmenter{mapping: map[string][]string{"alice@example.net": {"admins"}}}

	in := &user.DefaultInfo{
		Name:   "alice@example.net",
		UID:    "uid-1",
		Groups: []string{"from-token"},
		Extra:  map[string][]string{"foo": {"bar"}},
	}

	out := p.augmentGroups(in, "fakeAddr")

	if out.GetName() != in.GetName() || out.GetUID() != in.GetUID() {
		t.Errorf("expected name and uid to be preserved, got %q/%q", out.GetName(), out.GetUID())
	}

	if !reflect.DeepEqual(out.GetExtra(), in.GetExtra()) {
		t.Errorf("expected extra to be preserved, got %v", out.GetExtra())
	}

	groups := out.GetGroups()
	sort.Strings(groups)
	if !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Errorf("expected groups [admins], got %v", groups)
	}
}

// countingReviewer records whether the API server was consulted about an
// impersonation at all.
type countingReviewer struct {
	clientazv1.SubjectAccessReviewInterface
	calls int
}

func (c *countingReviewer) Create(ctx gocontext.Context, req *azv1.SubjectAccessReview,
	opts metav1.CreateOptions) (*azv1.SubjectAccessReview, error) {
	c.calls++
	return c.SubjectAccessReviewInterface.Create(ctx, req, opts)
}

// A request may not both carry impersonation headers and have its groups
// decided by the directory, since the headers would decide the groups instead.
//
// Every case here impersonates something the fake reviewer allows, so a refusal
// cannot be mistaken for RBAC having said no.
func TestImpersonationIsRefusedWhenAugmentationIsEnabled(t *testing.T) {
	tests := map[string]http.Header{
		"a user": {
			"Impersonate-User": []string{"jjackson"},
		},
		"a group": {
			"Impersonate-User":  []string{"jjackson"},
			"Impersonate-Group": []string{"group3"},
		},
		"a uid": {
			"Impersonate-User": []string{"jjackson"},
			"Impersonate-Uid":  []string{"1-2-3-4"},
		},
		"an extra": {
			"Impersonate-User":             []string{"jjackson"},
			"Impersonate-Extra-Remoteaddr": []string{"1.2.3.4"},
		},
	}

	for name, headers := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			defer p.ctrl.Finish()

			reviewer := &countingReviewer{
				SubjectAccessReviewInterface: fakesubjectaccessreview.New(nil),
			}
			p.subjectAccessReviewer, _ = subjectaccessreview.New(reviewer)

			p.ldapDirectory = &fakeAugmenter{
				mapping: map[string][]string{"alice@example.net": {"admins"}},
			}

			req := newADRequest("/api/v1/pods", http.MethodGet)
			for k, vs := range headers {
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

			resp := w.Result()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("got unexpected response code, exp=%d got=%d",
					http.StatusForbidden, resp.StatusCode)
			}

			// The refusal has to say why, or it reads as an RBAC decision the
			// caller could go and get themselves granted.
			if body := w.Body.String(); !strings.Contains(body, "group augmentation") {
				t.Errorf("expected the response to explain the refusal, got %q", body)
			}

			if proxied {
				t.Error("expected the request never to reach the API server")
			}

			// Refused before the check, so holding the RBAC to impersonate does
			// not get the headers honoured.
			if reviewer.calls != 0 {
				t.Errorf("expected no SubjectAccessReview to be created, got %d", reviewer.calls)
			}
		})
	}
}

// A request carrying no impersonation headers is still served, and still gets
// the groups of the directory.
func TestAugmentationStillServesRequestsWithoutImpersonation(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	p.ldapDirectory = &fakeAugmenter{mapping: map[string][]string{"alice@example.net": {"admins"}}}

	p.fakeRT.expUser = "alice@example.net"
	p.fakeRT.expGroup = []string{"admins", user.AllAuthenticated}

	resp := serveWithAD(t, p, newADRequest("/api/v1/pods", http.MethodGet),
		&user.DefaultInfo{Name: "alice@example.net", Groups: []string{"from-token"}})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusOK, resp.StatusCode)
	}
}
