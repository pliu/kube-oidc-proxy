// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/santhosh-tekuri/jsonschema/v6"
	k8sErrors "k8s.io/apimachinery/pkg/util/errors"
)

// Schema is the JSON schema every configuration file is checked against before
// it is decoded. It is published here so that it can be written out and used
// to check a configuration file ahead of a rollout.
//
//go:embed schema.json
var Schema []byte

// schemaURL is the identity the schema is compiled under. It is not fetched.
const schemaURL = "https://github.com/jetstack/kube-oidc-proxy/schemas/ldap-config.v1.json"

// Defaults applied to a configuration file that leaves a field out. They are
// duplicated in the "default" keywords of the schema, which are documentation
// only - the schema library does not write defaults into the instance.
const (
	DefaultUserFilter         = "(objectClass=user)"
	DefaultUsernameAttribute  = "userPrincipalName"
	DefaultGroupFilter        = "(objectClass=group)"
	DefaultGroupNameAttribute = "cn"
	DefaultRefreshInterval    = time.Minute * 10
	DefaultTimeout            = time.Minute * 5
	DefaultSecretKey          = "mapping.json.gz"
)

// CacheType selects the store the built mapping is persisted to.
type CacheType string

const (
	CacheTypeNone             CacheType = "none"
	CacheTypeFile             CacheType = "file"
	CacheTypeKubernetesSecret CacheType = "kubernetesSecret"
)

// Config is the decoded contents of an LDAP configuration file.
type Config struct {
	// Backends are the directories the mapping is built from. The mapping of
	// every backend is merged into one, so a user held in more than one
	// directory ends up with the union of their groups.
	Backends []*BackendConfig `json:"backends"`

	// RefreshInterval is a pointer so that a file asking for a refresh
	// interval of "0s" is rejected rather than quietly defaulted, which would
	// leave the mapping refreshing on a schedule nobody asked for.
	RefreshInterval *Duration `json:"refreshInterval,omitempty"`

	FallbackToTokenGroups bool `json:"fallbackToTokenGroups,omitempty"`

	// RefreshUsers is the set of users allowed to trigger a refresh. If empty,
	// any authenticated user may trigger one.
	RefreshUsers []string `json:"refreshUsers,omitempty"`

	// Cache describes where the built mapping is persisted. A nil cache, or one
	// of type "none", disables persistence.
	Cache *CacheConfig `json:"cache,omitempty"`

	// UsernamePrefix is not part of the configuration file. It is the OIDC
	// username prefix, threaded in from the OIDC options, and is stripped from
	// the username of a request before it is looked up in the mapping so that
	// the mapping can be keyed on the raw attribute value.
	UsernamePrefix string `json:"-"`
}

// BackendConfig describes one directory to build a mapping from.
type BackendConfig struct {
	Name string   `json:"name"`
	URLs []string `json:"urls"`

	BindDN           string `json:"bindDN,omitempty"`
	BindPassword     string `json:"bindPassword,omitempty"`
	BindPasswordFile string `json:"bindPasswordFile,omitempty"`

	CAFile                string `json:"caFile,omitempty"`
	InsecureSkipTLSVerify bool   `json:"insecureSkipTLSVerify,omitempty"`
	StartTLS              bool   `json:"startTLS,omitempty"`

	// Timeout bounds everything this backend does in one rebuild: connecting,
	// binding and every search. It is a pointer so that a file asking for a
	// timeout of "0s" is rejected rather than quietly taken to mean no bound
	// at all, which is the behaviour it reads as asking for.
	Timeout *Duration `json:"timeout,omitempty"`

	UserSearchBases   []string `json:"userSearchBases"`
	UserFilter        string   `json:"userFilter,omitempty"`
	UsernameAttribute string   `json:"usernameAttribute,omitempty"`

	GroupSearchBases   []string `json:"groupSearchBases"`
	GroupFilter        string   `json:"groupFilter,omitempty"`
	GroupNameAttribute string   `json:"groupNameAttribute,omitempty"`
	GroupPrefix        string   `json:"groupPrefix,omitempty"`
}

type CacheConfig struct {
	Type CacheType `json:"type"`

	// MaxAge is how old a persisted mapping may be and still be served at
	// startup. Zero serves a persisted mapping however old it is.
	MaxAge Duration `json:"maxAge,omitempty"`

	File             *FileCacheConfig   `json:"file,omitempty"`
	KubernetesSecret *SecretCacheConfig `json:"kubernetesSecret,omitempty"`
}

type FileCacheConfig struct {
	Path string `json:"path"`
}

type SecretCacheConfig struct {
	Name string `json:"name"`

	// Namespace defaults to the namespace the proxy is running in.
	Namespace string `json:"namespace,omitempty"`
	Key       string `json:"key,omitempty"`
}

// Duration is a time.Duration held in JSON as a string such as "10m", the form
// the flags it replaced took.
type Duration time.Duration

// Duration is nil safe, so that an unset optional duration reads as zero
// rather than panicking.
func (d *Duration) Duration() time.Duration {
	if d == nil {
		return 0
	}

	return time.Duration(*d)
}

func (d Duration) String() string { return time.Duration(d).String() }

// NewDuration returns a pointer to the given duration, for building a Config
// in code rather than reading one from a file.
func NewDuration(d time.Duration) *Duration {
	duration := Duration(d)
	return &duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("a duration must be a string such as \"10m\": %s", err)
	}

	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}

	*d = Duration(parsed)

	return nil
}

// LoadConfig reads the LDAP configuration from the given JSON
// file, checks it against the schema, applies defaults and validates the rules
// the schema cannot express.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read LDAP config file %q: %s", path, err)
	}

	config, err := ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("invalid LDAP config file %q: %s", path, err)
	}

	return config, nil
}

// ParseConfig checks, decodes and validates a configuration document.
func ParseConfig(data []byte) (*Config, error) {
	if err := ValidateSchema(data); err != nil {
		return nil, err
	}

	// The schema already rejects unknown properties. Decoding strictly as well
	// keeps a typo from being silently dropped should the two ever drift.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	config := new(Config)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}

	config.SetDefaults()

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// compileSchema compiles the embedded schema once, on first use.
var compileSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema))
	if err != nil {
		return nil, err
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaURL, doc); err != nil {
		return nil, err
	}

	return compiler.Compile(schemaURL)
})

// ValidateSchema reports whether the given document satisfies the schema.
func ValidateSchema(data []byte) error {
	schema, err := compileSchema()
	if err != nil {
		return fmt.Errorf("failed to compile the LDAP config schema: %s", err)
	}

	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to parse as JSON: %s", err)
	}

	if err := schema.Validate(instance); err != nil {
		var validationErr *jsonschema.ValidationError
		if errors.As(err, &validationErr) {
			// The rendering of a validation error is a tree of the keywords
			// that failed, which points at the offending field far better than
			// a one line summary can.
			return fmt.Errorf("does not match the config schema:\n%s", validationErr)
		}

		return err
	}

	return nil
}

// SetDefaults fills in the fields a configuration file is allowed to leave out.
func (c *Config) SetDefaults() {
	if c.RefreshInterval == nil {
		c.RefreshInterval = NewDuration(DefaultRefreshInterval)
	}

	for _, backend := range c.Backends {
		if backend == nil {
			continue
		}

		if backend.UserFilter == "" {
			backend.UserFilter = DefaultUserFilter
		}
		if backend.UsernameAttribute == "" {
			backend.UsernameAttribute = DefaultUsernameAttribute
		}
		if backend.GroupFilter == "" {
			backend.GroupFilter = DefaultGroupFilter
		}
		if backend.GroupNameAttribute == "" {
			backend.GroupNameAttribute = DefaultGroupNameAttribute
		}
		if backend.Timeout == nil {
			backend.Timeout = NewDuration(DefaultTimeout)
		}
	}

	if c.Cache == nil {
		return
	}

	if c.Cache.Type == "" {
		c.Cache.Type = CacheTypeNone
	}

	if c.Cache.KubernetesSecret != nil && c.Cache.KubernetesSecret.Key == "" {
		c.Cache.KubernetesSecret.Key = DefaultSecretKey
	}
}

// Validate checks the rules that the schema cannot express, and re-checks the
// structural rules so that a configuration built in code rather than read from
// a file is held to the same standard.
func (c *Config) Validate() error {
	var errs []error

	if len(c.Backends) == 0 {
		errs = append(errs, errors.New("at least one backend must be configured"))
	}

	names := make(map[string]struct{}, len(c.Backends))
	for i, backend := range c.Backends {
		if backend == nil {
			errs = append(errs, fmt.Errorf("backends[%d]: must not be null", i))
			continue
		}

		// Identify the backend by name where there is one, since the order of
		// the list means little to somebody reading the error.
		id := fmt.Sprintf("backends[%d]", i)
		if backend.Name != "" {
			id = fmt.Sprintf("backend %q", backend.Name)
		}

		if backend.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name must be set", id))
		} else if _, ok := names[backend.Name]; ok {
			errs = append(errs, fmt.Errorf("%s: duplicate backend name", id))
		}
		names[backend.Name] = struct{}{}

		errs = append(errs, backend.validate(id)...)
	}

	if c.RefreshInterval.Duration() <= 0 {
		errs = append(errs, errors.New("refreshInterval must be a positive duration"))
	}

	errs = append(errs, c.Cache.validate()...)

	return k8sErrors.NewAggregate(errs)
}

func (b *BackendConfig) validate(id string) []error {
	var errs []error

	if len(b.URLs) == 0 {
		errs = append(errs, fmt.Errorf("%s: at least one url must be set", id))
	}
	if len(b.UserSearchBases) == 0 {
		errs = append(errs, fmt.Errorf("%s: at least one userSearchBase must be set", id))
	}
	if len(b.GroupSearchBases) == 0 {
		errs = append(errs, fmt.Errorf("%s: at least one groupSearchBase must be set", id))
	}

	if b.BindPassword != "" && b.BindPasswordFile != "" {
		errs = append(errs, fmt.Errorf("%s: cannot set both bindPassword and bindPasswordFile", id))
	}
	if b.BindDN == "" && (b.BindPassword != "" || b.BindPasswordFile != "") {
		errs = append(errs, fmt.Errorf("%s: a bind password is set without a bindDN, which would bind anonymously", id))
	}

	if b.CAFile != "" && b.InsecureSkipTLSVerify {
		errs = append(errs, fmt.Errorf("%s: cannot set both caFile and insecureSkipTLSVerify", id))
	}

	if b.Timeout != nil && b.Timeout.Duration() <= 0 {
		errs = append(errs, fmt.Errorf("%s: timeout must be a positive duration", id))
	}

	return errs
}

func (c *CacheConfig) validate() []error {
	if c == nil {
		return nil
	}

	var errs []error

	switch c.Type {
	case CacheTypeNone:

	case CacheTypeFile:
		if c.File == nil || c.File.Path == "" {
			errs = append(errs, errors.New(`cache: file.path must be set when the cache type is "file"`))
		}

	case CacheTypeKubernetesSecret:
		if c.KubernetesSecret == nil || c.KubernetesSecret.Name == "" {
			errs = append(errs, errors.New(`cache: kubernetesSecret.name must be set when the cache type is "kubernetesSecret"`))
		}

	default:
		errs = append(errs, fmt.Errorf("cache: unknown type %q, must be one of none, file, kubernetesSecret", c.Type))
	}

	if c.MaxAge < 0 {
		errs = append(errs, errors.New("cache: maxAge must not be negative"))
	}

	return errs
}

// Enabled reports whether a mapping should actually be persisted.
func (c *CacheConfig) Enabled() bool {
	return c != nil && c.Type != "" && c.Type != CacheTypeNone
}

// bindPasswordFor resolves the password this backend binds with, reading it
// from disk if it was given as a file so that it need not sit in the config.
func (b *BackendConfig) bindPasswordFor() (string, error) {
	if b.BindPasswordFile == "" {
		return b.BindPassword, nil
	}

	password, err := os.ReadFile(b.BindPasswordFile)
	if err != nil {
		return "", fmt.Errorf("backend %q: failed to read bindPasswordFile %q: %s",
			b.Name, b.BindPasswordFile, err)
	}

	return strings.TrimRight(string(password), "\r\n"), nil
}

// mappingHash identifies the parts of the configuration that determine what a
// built mapping contains. A mapping persisted under a different hash describes
// a different directory layout, so it is discarded rather than served.
//
// Credentials, TLS settings and URLs are left out: they change how the
// directory is reached, not what the mapping ends up holding, and a password
// rotation should not throw away the persisted mapping.
func (c *Config) mappingHash() string {
	type backend struct {
		Name               string   `json:"name"`
		UserSearchBases    []string `json:"userSearchBases"`
		UserFilter         string   `json:"userFilter"`
		UsernameAttribute  string   `json:"usernameAttribute"`
		GroupSearchBases   []string `json:"groupSearchBases"`
		GroupFilter        string   `json:"groupFilter"`
		GroupNameAttribute string   `json:"groupNameAttribute"`
		GroupPrefix        string   `json:"groupPrefix"`
	}

	backends := make([]backend, 0, len(c.Backends))
	for _, b := range c.Backends {
		if b == nil {
			continue
		}

		backends = append(backends, backend{
			Name:               b.Name,
			UserSearchBases:    b.UserSearchBases,
			UserFilter:         b.UserFilter,
			UsernameAttribute:  b.UsernameAttribute,
			GroupSearchBases:   b.GroupSearchBases,
			GroupFilter:        b.GroupFilter,
			GroupNameAttribute: b.GroupNameAttribute,
			GroupPrefix:        b.GroupPrefix,
		})
	}

	// Marshalling a slice of structs is deterministic, so the same
	// configuration always hashes the same way.
	data, err := json.Marshal(backends)
	if err != nil {
		return ""
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}
