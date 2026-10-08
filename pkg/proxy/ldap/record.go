// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

// UserRecordFingerprint identifies membership and username mapping settings.
// Use on a defaulted, validated Config. Credentials, connection settings, and
// refresh intervals do not invalidate records; search settings and prefixes do.
func (c *Config) UserRecordFingerprint() string {
	data, _ := json.Marshal([]string{c.searchFingerprint(), c.UsernamePrefix})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NewUserRecord takes the canonical directory identity produced at the request
// boundary. A raw LDAP username may itself begin with the OIDC prefix, so that
// prefix must not be stripped again when creating or refreshing its record.
func (c *Config) NewUserRecord(username string, found bool, groups []string, checkedAt time.Time) (*cache.UserRecord, error) {
	return cache.NewUserRecord(username, found, groups, c.UserRecordFingerprint(), checkedAt)
}
