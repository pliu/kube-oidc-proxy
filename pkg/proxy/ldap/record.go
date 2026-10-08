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
	data, _ := json.Marshal([]string{c.mappingHash(), c.UsernamePrefix})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NewUserRecord applies the same username canonicalization used by LDAP lookups.
// Full group names are preserved in readable YAML.
func (c *Config) NewUserRecord(username string, found bool, groups []string, checkedAt time.Time) (*cache.UserRecord, error) {
	return cache.NewUserRecord(usernameKey(username, c.UsernamePrefix), found, groups, c.UserRecordFingerprint(), checkedAt)
}
