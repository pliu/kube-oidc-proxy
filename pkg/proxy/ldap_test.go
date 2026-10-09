// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	gocontext "context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

// fakeAugmenter stands in for a live LDAP backend.
type fakeAugmenter struct {
	mapping map[string][]string

	// refreshUsers is the set of users allowed to trigger a refresh. Empty
	// allows everyone, as the real directory does.
	refreshUsers []string

	resolveErr   error
	resolveCount int
}

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

func (f *fakeAugmenter) Resolve(ctx gocontext.Context, username string) ([]string, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	f.resolveCount++
	return f.mapping[username], nil
}

func (f *fakeAugmenter) Run(stopCh <-chan struct{}) error { return nil }

// serveWithLDAP runs a request that authenticates as tokenUser through the full
// handler chain, with the given directory in place.
func serveWithLDAP(t *testing.T, p *fakeProxy, req *http.Request, tokenUser user.Info) *http.Response {
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

func newLDAPRequest(path, method string) *http.Request {
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

			resp := serveWithLDAP(t, p, newLDAPRequest("/api/v1/pods", http.MethodGet), test.tokenUser)

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

	resp := serveWithLDAP(t, p, newLDAPRequest("/api/v1/pods", http.MethodGet),
		&user.DefaultInfo{Name: "alice@example.net", Groups: []string{"from-token"}})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusOK, resp.StatusCode)
	}
}

// The endpoint is a stub for now: it answers an allowed caller without
// resolving memberships or scheduling a refresh.
func TestLDAPRefreshEndpointIsAStub(t *testing.T) {
	tests := map[string]url.Values{
		"no query":      nil,
		"ignored query": {"user": {"bob@example.net"}},
	}

	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			defer p.ctrl.Finish()

			directory := &fakeAugmenter{mapping: map[string][]string{"alice@example.net": {"admins"}}}
			p.ldapDirectory = directory

			req := newLDAPRequest(LDAPRefreshPath, http.MethodPost)
			req.URL.RawQuery = query.Encode()

			resp := serveWithLDAP(t, p, req, &user.DefaultInfo{Name: "alice@example.net"})

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("got unexpected response code, exp=%d got=%d", http.StatusOK, resp.StatusCode)
			}

			if directory.resolveCount != 0 {
				t.Errorf("stub resolved memberships %d times", directory.resolveCount)
			}
		})
	}
}

func TestLDAPRefreshEndpointAllowedUsers(t *testing.T) {
	tests := map[string]struct {
		refreshUsers []string
		requester    string

		expCode int
	}{
		"any authenticated user may refresh when no users are configured": {
			refreshUsers: nil,
			requester:    "alice@example.net",
			expCode:      http.StatusOK,
		},
		"an allowed user may refresh": {
			refreshUsers: []string{"alice@example.net", "bob@example.net"},
			requester:    "bob@example.net",
			expCode:      http.StatusOK,
		},
		"a user not in the allowed users is forbidden": {
			refreshUsers: []string{"alice@example.net"},
			requester:    "eve@example.net",
			expCode:      http.StatusForbidden,
		},
		"a user not in a single entry allowed list is forbidden": {
			refreshUsers: []string{"alice@example.net"},
			requester:    "alice@example.net.evil",
			expCode:      http.StatusForbidden,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProxy(t)
			defer p.ctrl.Finish()

			directory := &fakeAugmenter{refreshUsers: test.refreshUsers}
			p.ldapDirectory = directory

			resp := serveWithLDAP(t, p, newLDAPRequest(LDAPRefreshPath, http.MethodPost),
				&user.DefaultInfo{Name: test.requester})

			if resp.StatusCode != test.expCode {
				t.Errorf("got unexpected response code, exp=%d got=%d",
					test.expCode, resp.StatusCode)
			}

			if directory.resolveCount != 0 {
				t.Errorf("expected no membership lookup, got %d", directory.resolveCount)
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

	req := newLDAPRequest(LDAPRefreshPath, http.MethodPost)
	req.Header = http.Header{}

	resp := serveWithLDAP(t, p, req, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusUnauthorized, resp.StatusCode)
	}

	if directory.resolveCount != 0 {
		t.Errorf("expected no membership lookup, got %d", directory.resolveCount)
	}
}

func TestLDAPRefreshEndpointRejectsGET(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	directory := &fakeAugmenter{}
	p.ldapDirectory = directory

	resp := serveWithLDAP(t, p, newLDAPRequest(LDAPRefreshPath, http.MethodGet),
		&user.DefaultInfo{Name: "alice@example.net"})

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusMethodNotAllowed, resp.StatusCode)
	}

	if directory.resolveCount != 0 {
		t.Errorf("expected no membership lookup, got %d", directory.resolveCount)
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

	resp := serveWithLDAP(t, p, newLDAPRequest(LDAPRefreshPath+"/subpath", http.MethodPost),
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

	out, err := p.augmentGroups(gocontext.Background(), in, "fakeAddr")
	if err != nil {
		t.Fatal(err)
	}

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

// A request carrying no impersonation headers is still served, and still gets
// the groups of the directory.
func TestAugmentationStillServesRequestsWithoutImpersonation(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()

	p.ldapDirectory = &fakeAugmenter{mapping: map[string][]string{"alice@example.net": {"admins"}}}

	p.fakeRT.expUser = "alice@example.net"
	p.fakeRT.expGroup = []string{"admins", user.AllAuthenticated}

	resp := serveWithLDAP(t, p, newLDAPRequest("/api/v1/pods", http.MethodGet),
		&user.DefaultInfo{Name: "alice@example.net", Groups: []string{"from-token"}})

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got unexpected response code, exp=%d got=%d",
			http.StatusOK, resp.StatusCode)
	}
}

func TestLDAPResolutionFailureReturnsServiceUnavailable(t *testing.T) {
	p := newTestProxy(t)
	defer p.ctrl.Finish()
	p.ldapDirectory = &fakeAugmenter{resolveErr: errors.New("persistence failed")}
	response := serveWithLDAP(t, p, newLDAPRequest("/api/v1/pods", http.MethodGet), &user.DefaultInfo{Name: "alice", Groups: []string{"from-token"}})
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", response.StatusCode)
	}
}
