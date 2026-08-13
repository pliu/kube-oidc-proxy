// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const minimalConfig = `{
  "backends": [
    {
      "name": "corp",
      "urls": ["ldaps://ldap.example.net:636"],
      "userSearchBases": ["OU=Users,DC=example,DC=net"],
      "groupSearchBases": ["OU=Groups,DC=example,DC=net"]
    }
  ],
  "cache": {"type": "none"}
}`

func TestParseConfigAppliesDefaults(t *testing.T) {
	config, err := ParseConfig([]byte(minimalConfig))
	if err != nil {
		t.Fatalf("unexpected error parsing config: %s", err)
	}

	if got := config.RefreshInterval.Duration(); got != DefaultRefreshInterval {
		t.Errorf("expected a default refresh interval of %s, got %s", DefaultRefreshInterval, got)
	}

	backend := config.Backends[0]

	tests := map[string]struct {
		got, exp string
	}{
		"userFilter":         {backend.UserFilter, DefaultUserFilter},
		"usernameAttribute":  {backend.UsernameAttribute, DefaultUsernameAttribute},
		"groupFilter":        {backend.GroupFilter, DefaultGroupFilter},
		"groupNameAttribute": {backend.GroupNameAttribute, DefaultGroupNameAttribute},
	}

	if got := backend.Timeout.Duration(); got != DefaultTimeout {
		t.Errorf("expected a default timeout of %s, got %s", DefaultTimeout, got)
	}

	for name, test := range tests {
		if test.got != test.exp {
			t.Errorf("expected a default %s of %q, got %q", name, test.exp, test.got)
		}
	}

	if config.Cache.Enabled() {
		t.Error(`expected persistence to be off when the cache type is "none"`)
	}
}

func TestParseConfigReadsEveryField(t *testing.T) {
	document := `{
  "backends": [
    {
      "name": "corp",
      "urls": ["ldaps://one.example.net:636", "ldaps://two.example.net:636"],
      "bindDN": "CN=svc,DC=example,DC=net",
      "bindPassword": "password",
      "caFile": "/etc/kube-oidc-proxy/ldap-ca.pem",
      "startTLS": true,
      "userSearchBases": ["OU=Users,DC=example,DC=net"],
      "userFilter": "(objectClass=person)",
      "usernameAttribute": "sAMAccountName",
      "groupSearchBases": ["OU=Groups,DC=example,DC=net"],
      "groupFilter": "(objectClass=groupOfNames)",
      "groupNameAttribute": "name",
      "groupPrefix": "corp:"
    },
    {
      "name": "partners",
      "urls": ["ldap://partners.example.net:389"],
      "insecureSkipTLSVerify": true,
      "userSearchBases": ["OU=Users,DC=partners,DC=net"],
      "groupSearchBases": ["OU=Groups,DC=partners,DC=net"],
      "groupPrefix": "partners:"
    }
  ],
  "refreshInterval": "1h30m",
  "fallbackToTokenGroups": true,
  "refreshUsers": ["alice@example.net"],
  "cache": {
    "type": "kubernetesSecret",
    "maxAge": "24h",
    "kubernetesSecret": {"name": "ldap-mapping", "namespace": "kube-oidc-proxy"}
  }
}`

	config, err := ParseConfig([]byte(document))
	if err != nil {
		t.Fatalf("unexpected error parsing config: %s", err)
	}

	if len(config.Backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(config.Backends))
	}

	if got := config.Backends[0].URLs; !reflect.DeepEqual(got, []string{"ldaps://one.example.net:636", "ldaps://two.example.net:636"}) {
		t.Errorf("expected both URLs, got %v", got)
	}
	if got := config.Backends[1].GroupPrefix; got != "partners:" {
		t.Errorf("expected a group prefix of \"partners:\", got %q", got)
	}
	if got := config.RefreshInterval.Duration(); got != time.Hour+time.Minute*30 {
		t.Errorf("expected a refresh interval of 1h30m, got %s", got)
	}
	if !config.FallbackToTokenGroups {
		t.Error("expected fallbackToTokenGroups to be set")
	}
	if got := config.Cache.MaxAge.Duration(); got != time.Hour*24 {
		t.Errorf("expected a maxAge of 24h, got %s", got)
	}
	if got := config.Cache.KubernetesSecret.Key; got != DefaultSecretKey {
		t.Errorf("expected a default Secret key of %q, got %q", DefaultSecretKey, got)
	}
	if !config.Cache.Enabled() {
		t.Error("expected persistence to be on")
	}
}

// The schema is what stands between a typo in a config file and a proxy that
// silently does not do what its operator meant.
func TestParseConfigRejectsBadDocuments(t *testing.T) {
	tests := map[string]struct {
		document string
		expErr   string
	}{
		"not JSON at all": {
			`backends: []`,
			"failed to parse as JSON",
		},
		"no backends": {
			`{"backends": []}`,
			"minItems",
		},
		"a missing backends property": {
			`{"refreshInterval": "10m"}`,
			"backends",
		},
		"a misspelled property": {
			`{"backends": [], "refreshIntervals": "10m"}`,
			"refreshIntervals",
		},
		// Where the mapping is persisted has to be stated, because leaving it
		// out gets a proxy that cannot start while a directory is down, and
		// nobody chooses that on purpose.
		"a missing cache property": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}]}`,
			"cache",
		},
		"a misspelled backend property": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBase": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}]}`,
			"userSearchBase",
		},
		"a backend with no name": {
			`{"backends": [{"urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}]}`,
			"name",
		},
		"a url of the wrong scheme": {
			`{"backends": [{"name": "corp", "urls": ["https://ldap.example.net"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}]}`,
			"pattern",
		},
		"a duration of the wrong shape": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "refreshInterval": "10 minutes"}`,
			"pattern",
		},
		"a refresh interval given as a number": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "refreshInterval": 600}`,
			"string",
		},
		"an unknown cache type": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "redis"}}`,
			"must be one of",
		},
		"a file cache with no file block": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "file"}}`,
			"file",
		},
		"a Secret cache with no kubernetesSecret block": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "kubernetesSecret"}}`,
			"kubernetesSecret",
		},
		"a Secret name that is not a valid object name": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "kubernetesSecret", "kubernetesSecret": {"name": "Not A Name"}}}`,
			"pattern",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig([]byte(test.document))
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", test.expErr)
			}

			if !strings.Contains(err.Error(), test.expErr) {
				t.Errorf("expected an error containing %q, got %q", test.expErr, err)
			}
		})
	}
}

// Rules that a JSON schema cannot express, and that are checked once the
// document has been decoded.
func TestValidateRejectsContradictoryConfigs(t *testing.T) {
	tests := map[string]struct {
		document string
		expErr   string
	}{
		"two backends of the same name": {
			`{"backends": [
			  {"name": "corp", "urls": ["ldaps://one.example.net:636"],
			   "userSearchBases": ["OU=Users,DC=example,DC=net"],
			   "groupSearchBases": ["OU=Groups,DC=example,DC=net"]},
			  {"name": "corp", "urls": ["ldaps://two.example.net:636"],
			   "userSearchBases": ["OU=Users,DC=example,DC=net"],
			   "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "none"}}`,
			"duplicate backend name",
		},
		"both a bind password and a bind password file": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "bindDN": "CN=svc,DC=example,DC=net",
			  "bindPassword": "password", "bindPasswordFile": "/etc/password",
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "none"}}`,
			"cannot set both bindPassword and bindPasswordFile",
		},
		"a bind password with no bind DN": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "bindPassword": "password",
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "none"}}`,
			"without a bindDN",
		},
		"both a CA file and skipped verification": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "caFile": "/etc/ca.pem", "insecureSkipTLSVerify": true,
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "none"}}`,
			"cannot set both caFile and insecureSkipTLSVerify",
		},
		"a refresh interval of zero": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "none"},
			  "refreshInterval": "0s"}`,
			"refreshInterval must be a positive duration",
		},
		"a timeout of zero": {
			`{"backends": [{"name": "corp", "urls": ["ldaps://ldap.example.net:636"],
			  "timeout": "0s",
			  "userSearchBases": ["OU=Users,DC=example,DC=net"],
			  "groupSearchBases": ["OU=Groups,DC=example,DC=net"]}],
			  "cache": {"type": "none"}}`,
			"timeout must be a positive duration",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig([]byte(test.document))
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", test.expErr)
			}

			if !strings.Contains(err.Error(), test.expErr) {
				t.Errorf("expected an error containing %q, got %q", test.expErr, err)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ldap.json")

	if err := os.WriteFile(path, []byte(minimalConfig), 0600); err != nil {
		t.Fatalf("unexpected error writing config: %s", err)
	}

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error loading config: %s", err)
	}

	if len(config.Backends) != 1 || config.Backends[0].Name != "corp" {
		t.Errorf("expected the config to have been loaded, got %+v", config)
	}

	// The path belongs in the error: an operator with several config files
	// needs to know which one is at fault.
	if _, err := LoadConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected an error loading a config file that does not exist")
	} else if !strings.Contains(err.Error(), "missing.json") {
		t.Errorf("expected the error to name the file, got %q", err)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"backends": []}`), 0600); err != nil {
		t.Fatalf("unexpected error writing config: %s", err)
	}

	if _, err := LoadConfig(bad); err == nil {
		t.Error("expected an error loading an invalid config file")
	} else if !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("expected the error to name the file, got %q", err)
	}
}

// The bind password is read from disk so that it need not sit in a config file
// that is often a ConfigMap.
func TestBindPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")

	// Trailing newlines are what an editor, or `kubectl create secret
	// --from-file`, leaves behind.
	if err := os.WriteFile(path, []byte("password\n"), 0600); err != nil {
		t.Fatalf("unexpected error writing password: %s", err)
	}

	backend := &BackendConfig{Name: "corp", BindPasswordFile: path}

	password, err := backend.bindPasswordFor()
	if err != nil {
		t.Fatalf("unexpected error reading the bind password: %s", err)
	}
	if password != "password" {
		t.Errorf("expected the password to be read and trimmed, got %q", password)
	}

	missing := &BackendConfig{Name: "corp", BindPasswordFile: filepath.Join(t.TempDir(), "missing")}
	if _, err := missing.bindPasswordFor(); err == nil {
		t.Error("expected an error reading a bind password file that does not exist")
	}

	inline := &BackendConfig{Name: "corp", BindPassword: "inline"}
	if password, err := inline.bindPasswordFor(); err != nil || password != "inline" {
		t.Errorf("expected the inline password, got %q (%v)", password, err)
	}
}

func TestDurationRoundTrips(t *testing.T) {
	type document struct {
		Interval Duration `json:"interval"`
	}

	var decoded document
	if err := json.Unmarshal([]byte(`{"interval": "1h30m"}`), &decoded); err != nil {
		t.Fatalf("unexpected error decoding duration: %s", err)
	}

	if got := decoded.Interval.Duration(); got != time.Hour+time.Minute*30 {
		t.Errorf("expected 1h30m, got %s", got)
	}

	encoded, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatalf("unexpected error encoding duration: %s", err)
	}

	if string(encoded) != `{"interval":"1h30m0s"}` {
		t.Errorf("expected the duration to be encoded as a string, got %s", encoded)
	}

	if err := json.Unmarshal([]byte(`{"interval": 600}`), &decoded); err == nil {
		t.Error("expected an error decoding a duration given as a number")
	}
}

// The schema is embedded, and a schema that does not compile would only be
// found the first time somebody used a config file.
func TestSchemaCompiles(t *testing.T) {
	if _, err := compileSchema(); err != nil {
		t.Fatalf("expected the embedded schema to compile: %s", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(Schema, &schema); err != nil {
		t.Fatalf("expected the embedded schema to be JSON: %s", err)
	}

	if got := schema["$id"]; got != schemaURL {
		t.Errorf("expected the schema to be identified as %q, got %q", schemaURL, got)
	}
}
