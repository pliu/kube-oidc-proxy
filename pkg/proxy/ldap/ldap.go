// Copyright Jetstack Ltd. See LICENSE for details.

// Package ldap augments the groups of an authenticated user with the groups
// they are a member of in one or more LDAP v3 directories - Active Directory,
// or anything else that exposes a memberOf attribute.
//
// Authenticated users are resolved on demand and persisted per identity.
// Only cached users are refreshed, and replicas synchronize through ConfigMaps.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const SourceCache = "cache"

var ErrNoBackends = errors.New("no LDAP backends configured")

// Stats summarizes valid records currently held in memory.
type Stats struct {
	Users       int       `json:"users"`
	Groups      int       `json:"groups"`
	LastRefresh time.Time `json:"lastRefresh"`
	Source      string    `json:"source,omitempty"`
}

// Directory is the LDAP resolver shared by per-user cache operations.
type Directory struct {
	config       *Config
	backends     []*backend
	refreshUsers map[string]struct{}
}

// backend is one directory the mapping is built from.
type backend struct {
	config    *BackendConfig
	tlsConfig *tls.Config

	// bindPassword is resolved up front, so that a refresh does not depend on
	// a file that may have gone away since startup.
	bindPassword string

	// groupBaseKeys are the configured group search bases, normalised the same
	// way a DN read from the directory is. A group a single user refresh has
	// never heard of is only worth looking at if it lives under one of them,
	// and that is a comparison rather than a search.
	groupBaseKeys []string

	dial func(url string) (conn, error)
}

// newResolver prepares LDAP backends without contacting the directories.
func newResolver(config *Config) (*Directory, error) {
	if config == nil {
		return nil, ErrNoBackends
	}

	// Defaulting here as well as when a config file is read holds a config
	// built in code to the same shape as one read from disk.
	config.SetDefaults()

	if len(config.Backends) == 0 {
		return nil, ErrNoBackends
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	backends := make([]*backend, 0, len(config.Backends))
	for _, backendConfig := range config.Backends {
		b, err := newBackend(backendConfig)
		if err != nil {
			return nil, err
		}

		backends = append(backends, b)
	}

	refreshUsers := make(map[string]struct{}, len(config.RefreshUsers))
	for _, username := range config.RefreshUsers {
		refreshUsers[usernameKey(username, config.UsernamePrefix)] = struct{}{}
	}

	d := &Directory{config: config, backends: backends, refreshUsers: refreshUsers}

	// Published from here rather than at init, so that a proxy running without
	// augmentation configured reports no series at all.
	registerMetrics()

	return d, nil
}

// newBackend prepares a backend to be searched. The configuration has already
// been validated by newResolver, so all that is left is the work that can fail against
// the filesystem: the trust bundle and the bind password.
func newBackend(config *BackendConfig) (*backend, error) {
	tlsConfig, err := tlsConfigFor(config)
	if err != nil {
		return nil, err
	}

	bindPassword, err := config.bindPasswordFor()
	if err != nil {
		return nil, err
	}

	b := &backend{
		config:       config,
		tlsConfig:    tlsConfig,
		bindPassword: bindPassword,
	}
	b.dial = b.dialLDAP

	// Parsed here rather than on the path that uses them, so that a search base
	// which is not a DN at all is reported where somebody is watching instead
	// of once per refresh of a user.
	for _, base := range config.GroupSearchBases {
		key, err := normaliseDN(base)
		if err != nil {
			return nil, fmt.Errorf("backend %q: groupSearchBase %q is not a valid DN: %s",
				config.Name, base, err)
		}

		b.groupBaseKeys = append(b.groupBaseKeys, key)
	}

	return b, nil
}

// CanRefresh reports whether the given user is allowed to trigger a refresh.
// With no allowed users configured, any user may - the endpoint already sits
// behind authentication.
func (d *Directory) CanRefresh(username string) bool {
	if len(d.refreshUsers) == 0 {
		return true
	}

	_, ok := d.refreshUsers[usernameKey(username, d.config.UsernamePrefix)]
	return ok
}

// usernameKey returns the one directory identity represented by a username.
// Authenticated requests carry the configured OIDC prefix, while LDAP entries
// carry the raw claim value. Strip the prefix before looking in either map so a
// prefixed request can never first capture a different LDAP entry whose raw
// username happens to begin with the same prefix.
func usernameKey(username, prefix string) string {
	if prefix != "" && strings.HasPrefix(username, prefix) {
		username = strings.TrimPrefix(username, prefix)
	}

	return strings.ToLower(username)
}

// eachBackend searches every backend in parallel and returns the results in
// configuration order. A refresh takes roughly as long as the slowest backend
// rather than the sum of all of them. The first error in configuration order
// is returned, so errors and results stay
// deterministic.
func eachBackend[T any](backends []*backend, fn func(*backend) (T, error)) ([]T, error) {
	type result struct {
		value T
		err   error
	}

	results := make([]result, len(backends))
	var wg sync.WaitGroup
	for i, b := range backends {
		wg.Add(1)
		go func() {
			defer wg.Done()

			value, err := fn(b)
			if err != nil {
				results[i].err = fmt.Errorf("backend %q: %s", b.config.Name, err)
				return
			}

			results[i].value = value
		}()
	}
	wg.Wait()

	values := make([]T, 0, len(results))
	for _, result := range results {
		if result.err != nil {
			return nil, result.err
		}

		values = append(values, result.value)
	}

	return values, nil
}
