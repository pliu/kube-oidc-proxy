// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

const (
	UserRecordVersion = 1
	// UserRecordKey is the ConfigMap data key containing the readable YAML record.
	UserRecordKey = "user.yaml"
)

// UserRecord persists one canonical directory identity. Groups are full names,
// never indices or compressed data. Found distinguishes an absent user from a
// user with no memberships; both are valid cache entries.
type UserRecord struct {
	Version                  int       `json:"version"`
	Username                 string    `json:"username"`
	Found                    bool      `json:"found"`
	Groups                   []string  `json:"groups"`
	ConfigurationFingerprint string    `json:"configurationFingerprint"`
	LastSuccessfulLookup     time.Time `json:"lastSuccessfulLookup"`
}

// NewUserRecord takes a canonical username supplied by the identity layer.
// Sorting and deduplication never alter a group name and never mutate the caller's slice.
func NewUserRecord(username string, found bool, groups []string, fingerprint string, checkedAt time.Time) (*UserRecord, error) {
	r := &UserRecord{
		Version: UserRecordVersion, Username: username, Found: found,
		Groups: append([]string{}, groups...), ConfigurationFingerprint: fingerprint,
		LastSuccessfulLookup: checkedAt.UTC(),
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	r.orderGroups()
	return r, nil
}

func (r *UserRecord) validate() error {
	if r == nil {
		return fmt.Errorf("nil user record")
	}
	if r.Version != UserRecordVersion {
		return fmt.Errorf("unsupported user record version %d", r.Version)
	}
	if strings.TrimSpace(r.Username) == "" || strings.TrimSpace(r.ConfigurationFingerprint) == "" {
		return fmt.Errorf("user record requires a username and configuration fingerprint")
	}
	if r.LastSuccessfulLookup.IsZero() {
		return fmt.Errorf("user record requires a last successful lookup time")
	}
	if !r.Found && len(r.Groups) != 0 {
		return fmt.Errorf("absent user cannot have group memberships")
	}
	for _, group := range r.Groups {
		if strings.TrimSpace(group) == "" || strings.HasPrefix(group, "system:") {
			return fmt.Errorf("invalid cached group %q", group)
		}
	}
	return nil
}

func (r *UserRecord) orderGroups() {
	sort.Strings(r.Groups)
	unique := r.Groups[:0]
	for _, group := range r.Groups {
		if len(unique) == 0 || group != unique[len(unique)-1] {
			unique = append(unique, group)
		}
	}
	r.Groups = unique
}

// EncodeUserRecord produces plain YAML with an explicit groups list, including
// groups: [] for an empty result. It does not modify the record.
func EncodeUserRecord(r *UserRecord) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	copy, err := NewUserRecord(r.Username, r.Found, r.Groups, r.ConfigurationFingerprint, r.LastSuccessfulLookup)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(copy)
}

// DecodeUserRecord validates both the document and its expected identity and
// configuration. Callers must supply the canonical username, even when loading
// an object whose name was derived from that username.
func DecodeUserRecord(data []byte, username, fingerprint string) (*UserRecord, error) {
	var r UserRecord
	if err := yaml.UnmarshalStrict(data, &r); err != nil {
		return nil, fmt.Errorf("decode user record: %w", err)
	}
	// Missing found must not silently become false, nor missing/null groups an
	// empty membership result. Both fields describe a successful LDAP answer.
	var required struct {
		Found  *bool     `json:"found"`
		Groups *[]string `json:"groups"`
	}
	if err := yaml.Unmarshal(data, &required); err != nil {
		return nil, fmt.Errorf("decode user record fields: %w", err)
	}
	if required.Found == nil || required.Groups == nil {
		return nil, fmt.Errorf("user record requires found and groups")
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	if r.Username != username || r.ConfigurationFingerprint != fingerprint {
		return nil, fmt.Errorf("user record identity or configuration does not match")
	}
	return NewUserRecord(r.Username, r.Found, r.Groups, r.ConfigurationFingerprint, r.LastSuccessfulLookup)
}

// UserConfigMapName hashes scope and canonical identity separately from LDAP
// configuration so a configuration change replaces the same user's record.
func UserConfigMapName(scope, username string) (string, error) {
	if strings.TrimSpace(scope) == "" || strings.TrimSpace(username) == "" {
		return "", fmt.Errorf("user ConfigMap name requires a cache scope and username")
	}
	data, err := json.Marshal([]string{scope, username})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "kube-oidc-proxy-user-" + hex.EncodeToString(sum[:]), nil
}
