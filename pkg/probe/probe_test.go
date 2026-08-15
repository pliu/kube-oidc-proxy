// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/jetstack/kube-oidc-proxy/pkg/util"
)

type fakeTokenAuthenticator struct {
	returnErr bool
}

var _ authenticator.Token = &fakeTokenAuthenticator{}

func (f *fakeTokenAuthenticator) AuthenticateToken(context.Context, string) (*authenticator.Response, bool, error) {
	if f.returnErr {
		return nil, false, errors.New("foo bar authenticator not initialized")
	}

	return nil, false, errors.New("some other error")
}

func TestRun(t *testing.T) {
	f := &fakeTokenAuthenticator{
		returnErr: true,
	}

	port, err := util.FreePort()
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}

	fakeJWT, err := util.FakeJWT("issuer")
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}

	ready := Run(port, fakeJWT, f)

	url := fmt.Sprintf("http://0.0.0.0:%s", port)

	var resp *http.Response
	var i int

	for {
		resp, err = http.Get(url + "/ready")
		if err == nil {
			break
		}

		if i >= 5 {
			t.Errorf("unexpected error: %s", err)
			t.FailNow()
		}
		i++
	}

	if resp.StatusCode != 503 {
		t.Errorf("expected ready probe to be responding and not ready, exp=%d got=%d",
			503, resp.StatusCode)
	}

	f.returnErr = false

	resp, err = http.Get(url + "/ready")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// OIDC is initialised, but the secure listener is not accepting yet.
	if resp.StatusCode != 503 {
		t.Errorf("expected ready probe to stay unready until serving, exp=%d got=%d",
			503, resp.StatusCode)
	}

	ready.MarkServing()

	resp, err = http.Get(url + "/ready")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected ready probe to be responding and ready, exp=%d got=%d",
			200, resp.StatusCode)
	}

	// Once the authenticator has returned with a non-initialised error, then
	// should always return ready.

	f.returnErr = true

	resp, err = http.Get(url + "/ready")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected ready probe to be responding and ready, exp=%d got=%d",
			200, resp.StatusCode)
	}
}

func TestCheckStaysUnreadyUntilServing(t *testing.T) {
	h := &HealthCheck{
		oidcAuther: &fakeTokenAuthenticator{},
		fakeJWT:    "unused",
	}

	if err := h.Check(); err == nil || err.Error() != "secure listener is not serving yet" {
		t.Fatalf("expected not serving yet, got %v", err)
	}

	h.MarkServing()

	if err := h.Check(); err != nil {
		t.Fatalf("expected ready once serving, got %v", err)
	}
}
