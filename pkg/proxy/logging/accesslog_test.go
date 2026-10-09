// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"net/http"
	"testing"
)

func TestXForwardedFor(t *testing.T) {

	tests := map[string]struct {
		headers    http.Header
		remoteAddr string
		exp        string
	}{
		"no x-forwarded-for": {
			headers:    http.Header{},
			remoteAddr: "1.2.3.4",
			exp:        "",
		},
		"empty x-forwarded-for": {
			headers: http.Header{
				"X-Forwarded-For": []string{""},
			},
			remoteAddr: "1.2.3.4",
			exp:        "",
		},
		"x-forwarded-for is remoteaddr": {
			headers: http.Header{
				"X-Forwarded-For": []string{"1.2.3.4"},
			},
			remoteAddr: "1.2.3.4",
			exp:        "",
		},
		"x-forwarded-for with no remoteaddr": {
			headers: http.Header{
				"X-Forwarded-For": []string{"1.2.3.1"},
			},
			remoteAddr: "1.2.3.4",
			exp:        "1.2.3.1",
		},
		"x-forwarded-for with with remoteaddr at the end": {
			headers: http.Header{
				"X-Forwarded-For": []string{"1.2.3.1, 1.2.3.4"},
			},
			remoteAddr: "1.2.3.4",
			exp:        "1.2.3.1",
		},
		"x-forwarded-for with with remoteaddr at the beginning": {
			headers: http.Header{
				"X-Forwarded-For": []string{"1.2.3.4, 1.2.3.1"},
			},
			remoteAddr: "1.2.3.4",
			exp:        "1.2.3.1",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			forwarded := findXForwardedFor(test.headers, test.remoteAddr)

			if test.exp != forwarded {
				t.Errorf("failed for %s: unexpected result : %s", name, forwarded)
				t.FailNow()
			}
		})
	}
}

func TestRemoteHost(t *testing.T) {
	tests := map[string]string{
		"1.2.3.4:5678":      "1.2.3.4",
		"[::1]:5678":        "::1",
		"[2001:db8::1]:443": "2001:db8::1",
		"1.2.3.4":           "1.2.3.4",
		"fakeAddr":          "fakeAddr",
		"":                  "",
	}

	for addr, exp := range tests {
		if got := remoteHost(addr); got != exp {
			t.Errorf("remoteHost(%q) = %q, exp %q", addr, got, exp)
		}
	}
}
