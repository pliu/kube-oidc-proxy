// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/jetstack/kube-oidc-proxy/pkg/util"
)

const (
	UserRecordVersion = 1
	// UserRecordKey is the ConfigMap data key containing the readable YAML record.
	UserRecordKey = "user.yaml"
)

// UserRecord persists one canonical directory identity. Groups are full names,
// stored directly in readable YAML. Found distinguishes an absent user from a
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
		Groups: groups, ConfigurationFingerprint: fingerprint,
		LastSuccessfulLookup: checkedAt,
	}
	return r.normalized()
}

func (r *UserRecord) validate() error {
	if r == nil {
		return errors.New("nil user record")
	}
	if r.Version != UserRecordVersion {
		return fmt.Errorf("unsupported user record version %d", r.Version)
	}
	if strings.TrimSpace(r.Username) == "" || strings.TrimSpace(r.ConfigurationFingerprint) == "" {
		return errors.New("user record requires a username and configuration fingerprint")
	}
	if r.LastSuccessfulLookup.IsZero() {
		return errors.New("user record requires a last successful lookup time")
	}
	if !r.Found && len(r.Groups) != 0 {
		return errors.New("absent user cannot have group memberships")
	}
	for _, group := range r.Groups {
		if strings.TrimSpace(group) == "" || strings.HasPrefix(group, "system:") {
			return fmt.Errorf("invalid cached group %q", group)
		}
	}
	return nil
}

func (r *UserRecord) orderGroups() {
	slices.Sort(r.Groups)
	r.Groups = slices.Compact(r.Groups)
}

// normalized validates once and returns an independent record with canonical
// group ordering and UTC time. Neither the record nor its input slice changes.
func (r *UserRecord) normalized() (*UserRecord, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	copy := *r
	copy.Groups = append([]string{}, r.Groups...)
	copy.LastSuccessfulLookup = r.LastSuccessfulLookup.UTC()
	copy.orderGroups()
	return &copy, nil
}

// EncodeUserRecord produces plain YAML with an explicit groups list, including
// groups: [] for an empty result. It does not modify the record.
func EncodeUserRecord(r *UserRecord) ([]byte, error) {
	copy, err := r.normalized()
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(copy)
}

// DecodeUserRecord validates both the document and its expected identity and
// configuration. Callers must supply the canonical username, even when loading
// an object whose name was derived from that username.
func DecodeUserRecord(data []byte, username, fingerprint string) (*UserRecord, error) {
	r, err := decodeUserRecord(data, fingerprint)
	if err != nil {
		return nil, err
	}
	if r.Username != username {
		return nil, errors.New("user record identity or configuration does not match")
	}
	return r, nil
}

// decodeUserRecord parses the complete document once. Pointers distinguish
// omitted/null required fields from valid false and empty-list values.
func decodeUserRecord(data []byte, fingerprint string) (*UserRecord, error) {
	var document struct {
		Version                  int       `json:"version"`
		Username                 string    `json:"username"`
		Found                    *bool     `json:"found"`
		Groups                   *[]string `json:"groups"`
		ConfigurationFingerprint string    `json:"configurationFingerprint"`
		LastSuccessfulLookup     time.Time `json:"lastSuccessfulLookup"`
	}
	if err := yaml.UnmarshalStrict(data, &document); err != nil {
		return nil, fmt.Errorf("decode user record: %w", err)
	}
	if document.Found == nil || document.Groups == nil {
		return nil, errors.New("user record requires found and groups")
	}
	r := &UserRecord{
		Version: document.Version, Username: document.Username, Found: *document.Found, Groups: *document.Groups,
		ConfigurationFingerprint: document.ConfigurationFingerprint, LastSuccessfulLookup: document.LastSuccessfulLookup,
	}
	if r.ConfigurationFingerprint != fingerprint {
		return nil, errors.New("user record identity or configuration does not match")
	}
	return r.normalized()
}

// UserConfigMapName hashes scope and canonical identity separately from LDAP
// configuration so a configuration change replaces the same user's record.
func UserConfigMapName(scope, username string) (string, error) {
	if strings.TrimSpace(scope) == "" || strings.TrimSpace(username) == "" {
		return "", errors.New("user ConfigMap name requires a cache scope and username")
	}
	return "kube-oidc-proxy-user-" + util.HashJSON([]string{scope, username}), nil
}
