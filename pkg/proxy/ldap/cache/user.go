// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const (
	UserRecordVersion = 1
	// UserRecordKey is the ConfigMap data key containing the readable YAML record.
	UserRecordKey = "user.yaml"
)

// UserRecord persists one canonical directory identity. Groups are full names,
// stored directly in readable YAML. Empty memberships, including absent users,
// are valid cache entries.
type UserRecord struct {
	Version                  int       `json:"version"`
	Username                 string    `json:"username"`
	Groups                   []string  `json:"groups"`
	ConfigurationFingerprint string    `json:"configurationFingerprint"`
	LastSuccessfulLookup     time.Time `json:"lastSuccessfulLookup"`
}

// NewUserRecord takes a canonical username supplied by the identity layer.
// Sorting and deduplication never alter a group name and never mutate the caller's slice.
func NewUserRecord(username string, groups []string, fingerprint string, checkedAt time.Time) (*UserRecord, error) {
	r := &UserRecord{
		Version: UserRecordVersion, Username: username,
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
// omitted/null required fields from valid empty-list values.
func decodeUserRecord(data []byte, fingerprint string) (*UserRecord, error) {
	var document struct {
		Version                  int       `json:"version"`
		Username                 string    `json:"username"`
		Groups                   *[]string `json:"groups"`
		ConfigurationFingerprint string    `json:"configurationFingerprint"`
		LastSuccessfulLookup     time.Time `json:"lastSuccessfulLookup"`
	}
	if err := yaml.UnmarshalStrict(data, &document); err != nil {
		return nil, fmt.Errorf("decode user record: %w", err)
	}
	if document.Groups == nil {
		return nil, errors.New("user record requires groups")
	}
	r := &UserRecord{
		Version: document.Version, Username: document.Username, Groups: *document.Groups,
		ConfigurationFingerprint: document.ConfigurationFingerprint, LastSuccessfulLookup: document.LastSuccessfulLookup,
	}
	if r.ConfigurationFingerprint != fingerprint {
		return nil, errors.New("user record identity or configuration does not match")
	}
	return r.normalized()
}

// userConfigMapPrefix starts the name of every user ConfigMap.
const userConfigMapPrefix = "kube-oidc-proxy-user-"

// UserConfigMapName derives a readable ConfigMap name from the canonical
// username, so an operator can find a user's record by name. It is independent
// of LDAP configuration, so a configuration change replaces the same record.
//
// A ConfigMap name must be a DNS subdomain, so characters it cannot hold become
// '-', a '.' that would not sit between two letters or digits becomes '-', and
// names over the length limit are cut short. Distinct usernames can therefore
// share a name; the record's username field, not the name, identifies its user.
func UserConfigMapName(username string) (string, error) {
	if strings.TrimSpace(username) == "" {
		return "", errors.New("user ConfigMap name requires a username")
	}

	mapped := []byte(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' {
			return r
		}
		return '-'
	}, strings.ToLower(username)))
	// strings.Map replaced every non-ASCII rune with one '-', so the result is ASCII.
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	for i, c := range mapped {
		// The prefix ends in '-', so a leading '.' never follows a letter or digit.
		if c == '.' && (i == 0 || !alnum(mapped[i-1]) || i == len(mapped)-1 || !alnum(mapped[i+1])) {
			mapped[i] = '-'
		}
	}

	name := userConfigMapPrefix + string(mapped)
	if len(name) > validation.DNS1123SubdomainMaxLength {
		name = name[:validation.DNS1123SubdomainMaxLength]
	}
	// A name must end in a letter or digit; the prefix guarantees one remains.
	return strings.TrimRight(name, "-."), nil
}
