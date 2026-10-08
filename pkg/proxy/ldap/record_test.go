// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"testing"
	"time"
)

func TestUserRecordCanonicalIdentity(t *testing.T) {
	c := testConfig()
	c.UsernamePrefix = "oidc:"
	r, err := c.NewUserRecord("oidc:alice@example.net", true, []string{"Developers"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.Username != "oidc:alice@example.net" || r.ConfigurationFingerprint != c.UserRecordFingerprint() {
		t.Fatalf("incorrect identity/configuration: %#v", r)
	}
}

func TestUserRecordFingerprint(t *testing.T) {
	base := testConfig().UserRecordFingerprint()
	tests := []struct {
		name        string
		change      func(*Config)
		invalidates bool
	}{
		{"prefix", func(c *Config) { c.UsernamePrefix += "different:" }, true},
		{"user filter", func(c *Config) { c.Backends[0].UserFilter = "(objectClass=person)" }, true},
		{"group attribute", func(c *Config) { c.Backends[0].GroupNameAttribute = "displayName" }, true},
		{"credentials", func(c *Config) { c.Backends[0].BindPassword = "rotated" }, false},
		{"URLs", func(c *Config) { c.Backends[0].URLs = []string{"ldaps://replacement.example.net"} }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := testConfig()
			test.change(c)
			if changed := c.UserRecordFingerprint() != base; changed != test.invalidates {
				t.Fatalf("fingerprint changed=%t, want %t", changed, test.invalidates)
			}
		})
	}
}
