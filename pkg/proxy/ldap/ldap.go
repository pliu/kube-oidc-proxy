// Copyright Jetstack Ltd. See LICENSE for details.

// Package ldap augments the groups of an authenticated user with the groups
// they are a member of in one or more LDAP v3 directories - Active Directory,
// or anything else that exposes a memberOf attribute.
//
// The full user -> group mapping is built up front from every configured
// backend and merged into one, held in memory. It is rebuilt on an interval,
// or on demand, and swapped in atomically so that in flight requests always
// read a complete, consistent mapping.
//
// The built mapping can also be persisted, so that a proxy restarted while the
// directories are unreachable serves the last mapping it built rather than
// stripping every user of their groups.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

const (
	// SourceDirectory and SourceCache describe where the mapping currently
	// being served came from.
	SourceDirectory = "directory"
	SourceCache     = "cache"
)

// ErrNoBackends is returned when there is no directory to build a mapping
// from. Every other configuration problem is reported by Config.Validate.
var ErrNoBackends = errors.New("no LDAP backends configured")

// Stats describes the state of the currently active mapping.
type Stats struct {
	Users       int       `json:"users"`
	Groups      int       `json:"groups"`
	LastRefresh time.Time `json:"lastRefresh"`
	Duration    string    `json:"duration"`

	// Source is where the active mapping came from: the directories
	// themselves, or the persisted cache after a failed startup refresh.
	Source string `json:"source,omitempty"`

	Backends []BackendStats `json:"backends,omitempty"`
}

// BackendStats describes what one backend contributed to the mapping.
type BackendStats struct {
	Name     string `json:"name"`
	Users    int    `json:"users"`
	Groups   int    `json:"groups"`
	Duration string `json:"duration"`
}

type Directory struct {
	config   *Config
	backends []*backend

	// cache persists the built mapping. Nil when persistence is disabled.
	cache cache.Store

	// persisted is what the cache is taken to already hold, so that a refresh
	// which rebuilds the same mapping does not rewrite it, and a change
	// reported by the store can be told from the mapping already being served.
	//
	// Only the refresh path writes it, and Refresh serialises that. It is a
	// pointer so that a store watching for changes can read it from a
	// goroutine of its own.
	persisted atomic.Pointer[persistedSnapshot]

	// mappingHash identifies the configuration the mapping is built from, so
	// that a mapping persisted under a different configuration is not served.
	mappingHash string

	// mapping is the active username -> groups mapping. It is only ever
	// replaced, never mutated, so readers need no locking.
	mapping atomic.Pointer[map[string][]string]
	stats   atomic.Pointer[Stats]

	// updateGate serialises every directory read that can replace some or all
	// of the mapping. A channel rather than a mutex lets a single-user request
	// stop waiting when its context is cancelled; see lockUpdate.
	updateGate chan struct{}

	// refreshMu guards inflight. It is not held across a rebuild.
	refreshMu sync.Mutex

	// inflight is the rebuild currently running, if one is. A caller arriving
	// while it runs waits for it rather than starting another.
	inflight *refreshCall

	// refreshUsers holds the lower cased names of the users allowed to trigger
	// a refresh. Empty means any authenticated user may.
	refreshUsers map[string]struct{}
}

// backend is one directory the mapping is built from.
type backend struct {
	config    *BackendConfig
	tlsConfig *tls.Config

	// bindPassword is resolved up front, so that a refresh does not depend on
	// a file that may have gone away since startup.
	bindPassword string

	// lastUsers and lastGroups are what this backend returned at the last
	// refresh that was accepted, so that a backend which still answers but has
	// stopped returning anything can be told apart from one that was always
	// empty. Written only by the refresh path, which Refresh serialises, and
	// by restore before the first refresh.
	lastUsers  int
	lastGroups int

	// lastGroupNames is the normalised group DN -> emitted name mapping of the
	// last accepted refresh. Refreshing one user resolves their memberOf
	// against it rather than sweeping every group search base again, which is
	// most of what makes that cheaper than rebuilding everybody.
	//
	// Read while a refresh of a single user runs, which is not the goroutine
	// that wrote it, so it is swapped rather than written into.
	lastGroupNames atomic.Pointer[map[string]string]

	// groupBaseKeys are the configured group search bases, normalised the same
	// way a DN read from the directory is. A group a single user refresh has
	// never heard of is only worth looking at if it lives under one of them,
	// and that is a comparison rather than a search.
	groupBaseKeys []string

	dial func(url string) (conn, error)
}

// New builds a Directory from a validated configuration. The store may be nil,
// in which case the mapping is not persisted.
func New(config *Config, store cache.Store) (*Directory, error) {
	if config == nil {
		return nil, ErrNoBackends
	}

	// Defaulting here as well as when a config file is read holds a config
	// built in code to the same shape as one read from disk.
	config.SetDefaults()

	// A reader is meant to have no backends: it serves what a builder
	// published and never opens a directory itself.
	if config.Role.Builds() && len(config.Backends) == 0 {
		return nil, ErrNoBackends
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if !config.Role.Builds() && store == nil {
		return nil, fmt.Errorf("the %q role has no store to read the mapping from", config.Role)
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

	d := &Directory{
		config:       config,
		backends:     backends,
		cache:        store,
		mappingHash:  config.mappingHash(),
		refreshUsers: refreshUsers,
		updateGate:   make(chan struct{}, 1),
	}
	d.updateGate <- struct{}{}

	empty := make(map[string][]string)
	d.mapping.Store(&empty)
	d.stats.Store(&Stats{})

	// Published from here rather than at init, so that a proxy running without
	// augmentation configured reports no series at all. Every backend starts
	// with a series of its own, so that "no duplicates" is a zero rather than
	// an absence an alert cannot tell from a backend that never ran.
	registerMetrics()
	for _, b := range backends {
		backendDuplicateValues.WithLabelValues(b.config.Name, duplicateKindUser).Set(0)
		backendDuplicateValues.WithLabelValues(b.config.Name, duplicateKindGroup).Set(0)
	}

	return d, nil
}

// newBackend prepares a backend to be searched. The configuration has already
// been validated by New, so all that is left is the work that can fail against
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

// HasMapping reports whether this proxy has ever got hold of a mapping. Until
// it has, it would answer every request by stripping the user of their groups,
// so it must not be sent any.
//
// It asks whether a mapping arrived rather than whether it holds any users: a
// directory that legitimately matches nobody is a mapping like any other, and
// a proxy serving it is working exactly as it was configured to.
func (d *Directory) HasMapping() bool {
	return !d.stats.Load().LastRefresh.IsZero()
}

// Groups returns the directory groups of the given username. The second return
// value reports whether the user was found in any backend at all - a user that
// exists but is in none of the configured groups returns an empty slice and
// true.
func (d *Directory) Groups(username string) ([]string, bool) {
	mapping := *d.mapping.Load()
	groups, ok := mapping[usernameKey(username, d.config.UsernamePrefix)]
	return groups, ok
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

// RefreshEndpointEnabled reports whether this proxy reaches the directories
// and can therefore serve the endpoint that asks for a rebuild. Readers learn
// about published mappings through their store watcher instead.
func (d *Directory) RefreshEndpointEnabled() bool {
	return d.config.Role.Builds()
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

func (d *Directory) Stats() *Stats {
	return d.stats.Load()
}

// eachBackend searches every backend in parallel and returns the results in
// configuration order. A refresh takes roughly as long as the slowest backend
// rather than the sum of all of them. The first error in configuration order
// is returned, so errors, statistics and the persisted snapshot stay
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
