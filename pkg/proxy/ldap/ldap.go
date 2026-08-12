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
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

const (
	// pageSize is the LDAP paging size used for searches. 1000 is the default
	// MaxPageSize of an Active Directory domain controller.
	pageSize = 1000

	// memberOfAttribute holds the DNs of the groups an entry belongs to.
	memberOfAttribute = "memberOf"

	// cacheTimeout bounds a read or write of the persisted mapping, so that an
	// unresponsive store cannot hold up a refresh indefinitely.
	cacheTimeout = time.Second * 30

	// SourceDirectory and SourceCache describe where the mapping currently
	// being served came from.
	SourceDirectory = "directory"
	SourceCache     = "cache"
)

// ErrNoBackends is returned when there is no directory to build a mapping
// from. Every other configuration problem is reported by Config.Validate.
var ErrNoBackends = errors.New("no LDAP backends configured")

// conn is the subset of *goldap.Conn used by a backend, so that the search
// behaviour can be exercised without a live directory.
type conn interface {
	StartTLS(*tls.Config) error
	Bind(username, password string) error
	SearchWithPaging(req *goldap.SearchRequest, pagingSize uint32) (*goldap.SearchResult, error)
	Close() error
}

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

	// mappingHash identifies the configuration the mapping is built from, so
	// that a mapping persisted under a different configuration is not served.
	mappingHash string

	// mapping is the active username -> groups mapping. It is only ever
	// replaced, never mutated, so readers need no locking.
	mapping atomic.Pointer[map[string][]string]
	stats   atomic.Pointer[Stats]

	// refreshMu serialises refreshes so that a burst of requests to the
	// refresh endpoint cannot fan out into a burst of directory searches.
	refreshMu sync.Mutex

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

	dial func(url string) (conn, error)
}

// New builds a Directory from a validated configuration. The store may be nil,
// in which case the mapping is not persisted.
func New(config *Config, store cache.Store) (*Directory, error) {
	if config == nil || len(config.Backends) == 0 {
		return nil, ErrNoBackends
	}

	// Defaulting here as well as when a config file is read holds a config
	// built in code to the same shape as one read from disk.
	config.SetDefaults()

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
		refreshUsers[strings.ToLower(username)] = struct{}{}
	}

	d := &Directory{
		config:       config,
		backends:     backends,
		cache:        store,
		mappingHash:  config.mappingHash(),
		refreshUsers: refreshUsers,
	}

	empty := make(map[string][]string)
	d.mapping.Store(&empty)
	d.stats.Store(&Stats{})

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

	return b, nil
}

// Run builds the initial mapping and then keeps it refreshed until stopCh is
// closed.
//
// The initial refresh is synchronous: starting to serve requests with an empty
// mapping would silently strip every user of their groups. A persisted mapping
// is loaded first so that it can stand in if that refresh fails, and only when
// there is no mapping to fall back on does a failure stop the proxy starting.
func (d *Directory) Run(stopCh <-chan struct{}) error {
	restored := d.restore()

	if err := d.Refresh(); err != nil {
		if !restored {
			return fmt.Errorf("failed to build initial LDAP mapping: %s", err)
		}

		klog.Errorf("failed to build initial LDAP mapping, serving the mapping persisted in %s: %s",
			d.cache, err)
	}

	go func() {
		ticker := time.NewTicker(d.config.RefreshInterval.Duration())
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return

			case <-ticker.C:
				if err := d.Refresh(); err != nil {
					// Keep serving the previous mapping rather than failing
					// every request while a directory is unreachable.
					klog.Errorf("failed to refresh LDAP mapping, keeping previous mapping: %s", err)
				}
			}
		}
	}()

	return nil
}

// Refresh rebuilds the user -> group mapping from every backend and atomically
// swaps it in. The previous mapping is left in place if the rebuild fails.
func (d *Directory) Refresh() error {
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()

	start := time.Now()

	mapping, groups, backendStats, err := d.build()
	if err != nil {
		return err
	}

	d.mapping.Store(&mapping)
	d.stats.Store(&Stats{
		Users:       len(mapping),
		Groups:      groups,
		LastRefresh: start,
		Duration:    time.Since(start).String(),
		Source:      SourceDirectory,
		Backends:    backendStats,
	})

	klog.V(2).Infof("refreshed LDAP mapping from %d backends: %d users, %d groups (%s)",
		len(d.backends), len(mapping), groups, time.Since(start))

	d.persist(mapping, groups, start, backendStats)

	return nil
}

// Groups returns the directory groups of the given username. The second return
// value reports whether the user was found in any backend at all - a user that
// exists but is in none of the configured groups returns an empty slice and
// true.
func (d *Directory) Groups(username string) ([]string, bool) {
	mapping := *d.mapping.Load()

	if groups, ok := mapping[strings.ToLower(username)]; ok {
		return groups, true
	}

	// The username of the request carries the OIDC username prefix, whereas
	// the directory is keyed on the bare attribute value.
	if p := d.config.UsernamePrefix; p != "" && strings.HasPrefix(username, p) {
		groups, ok := mapping[strings.ToLower(strings.TrimPrefix(username, p))]
		return groups, ok
	}

	return nil, false
}

// CanRefresh reports whether the given user is allowed to trigger a refresh.
// With no allowed users configured, any user may - the endpoint already sits
// behind authentication.
func (d *Directory) CanRefresh(username string) bool {
	if len(d.refreshUsers) == 0 {
		return true
	}

	if _, ok := d.refreshUsers[strings.ToLower(username)]; ok {
		return true
	}

	// Allow the allowed users to be given either as they appear in the token
	// or without the OIDC username prefix, matching how users are looked up in
	// the directory.
	if p := d.config.UsernamePrefix; p != "" && strings.HasPrefix(username, p) {
		_, ok := d.refreshUsers[strings.ToLower(strings.TrimPrefix(username, p))]
		return ok
	}

	return false
}

// FallbackToTokenGroups reports whether users missing from every directory
// keep the groups from their token.
func (d *Directory) FallbackToTokenGroups() bool {
	return d.config.FallbackToTokenGroups
}

func (d *Directory) Stats() *Stats {
	return d.stats.Load()
}

// build searches every backend and returns the merged username -> groups
// mapping, along with the number of distinct groups that were considered.
//
// A backend that cannot be searched, or that has stopped returning anything at
// all, fails the whole refresh. Merging what the healthy backends returned
// would quietly drop the groups a user holds in the other one, which is worse
// than serving a mapping that is a refresh interval out of date.
func (d *Directory) build() (map[string][]string, int, []BackendStats, error) {
	mapping := make(map[string][]string)
	stats := make([]BackendStats, 0, len(d.backends))

	var groups int

	for _, b := range d.backends {
		start := time.Now()

		built, builtGroups, err := b.build()
		if err != nil {
			return nil, 0, nil, fmt.Errorf("backend %q: %s", b.config.Name, err)
		}

		if err := b.observe(len(built), builtGroups); err != nil {
			return nil, 0, nil, fmt.Errorf("backend %q: %s", b.config.Name, err)
		}

		merge(mapping, built)
		groups += builtGroups

		stats = append(stats, BackendStats{
			Name:     b.config.Name,
			Users:    len(built),
			Groups:   builtGroups,
			Duration: time.Since(start).String(),
		})

		klog.V(4).Infof("built LDAP mapping from backend %q: %d users, %d groups (%s)",
			b.config.Name, len(built), builtGroups, time.Since(start))
	}

	finalise(mapping)

	return mapping, groups, stats, nil
}

// merge folds the mapping of one backend into the combined mapping. A user
// held in more than one directory ends up with the union of their groups.
func merge(into, from map[string][]string) {
	for username, groups := range from {
		existing, ok := into[username]
		if !ok {
			into[username] = groups
			continue
		}

		// Two directories can name the same group, and a user must not be
		// impersonated as a member of it twice.
		seen := make(map[string]struct{}, len(existing))
		for _, group := range existing {
			seen[group] = struct{}{}
		}

		for _, group := range groups {
			if _, duplicate := seen[group]; duplicate {
				continue
			}

			seen[group] = struct{}{}
			existing = append(existing, group)
		}

		into[username] = existing
	}
}

// finalise sorts the groups of every user, so that the mapping does not depend
// on the order the backends happened to return, and clips each slice to its
// length. The mapping is shared by every request, so a caller appending to the
// groups of a user then gets a copy rather than writing into spare capacity
// that other requests can see.
func finalise(mapping map[string][]string) {
	for username, groups := range mapping {
		sort.Strings(groups)
		mapping[username] = groups[:len(groups):len(groups)]
	}
}

// build searches this backend and returns a username -> groups mapping, along
// with the number of distinct groups that were considered.
func (b *backend) build() (map[string][]string, int, error) {
	c, err := b.connect()
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()

	// Only groups that live under one of the configured search bases are
	// pulled, so the mapping is restricted to the intended part of the tree.
	groupNames, err := b.searchGroups(c)
	if err != nil {
		return nil, 0, err
	}

	mapping, err := b.searchUsers(c, groupNames)
	if err != nil {
		return nil, 0, err
	}

	return mapping, len(groupNames), nil
}

// observe records what a backend returned, rejecting one that has stopped
// returning anything at all.
//
// A search that comes back empty is not an error at the protocol level, so
// without this a backend that answers but finds nothing is merged in as a
// backend that contributes nothing: a bind account that loses its read on the
// user OU, or a search base renamed out from under the configuration, silently
// strips every user of that directory of their groups. Treating the collapse
// as a failure keeps the last good mapping serving instead, which is the same
// choice made for a backend that cannot be reached at all.
//
// Only a fall to zero is caught, not a directory that merely shrinks - any
// threshold short of that would be a guess at how much churn is normal. A
// directory that has legitimately been emptied is accepted once the proxy is
// restarted and its persisted mapping removed.
func (b *backend) observe(users, groups int) error {
	switch {
	case b.lastUsers > 0 && users == 0:
		return fmt.Errorf("returned no users, having returned %d at the last refresh", b.lastUsers)

	case b.lastGroups > 0 && groups == 0:
		return fmt.Errorf("returned no groups, having returned %d at the last refresh", b.lastGroups)
	}

	b.lastUsers, b.lastGroups = users, groups

	return nil
}

// searchGroups returns a mapping of normalised group DN -> group name for
// every group under the configured group search bases.
func (b *backend) searchGroups(c conn) (map[string]string, error) {
	groupNames := make(map[string]string)

	for _, base := range b.config.GroupSearchBases {
		req := goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, 0, false, b.config.GroupFilter, []string{b.config.GroupNameAttribute}, nil)

		res, err := c.SearchWithPaging(req, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to search groups in %q: %s", base, err)
		}

		for _, entry := range res.Entries {
			name := entry.GetAttributeValue(b.config.GroupNameAttribute)
			if name == "" {
				klog.V(4).Infof("skipping group %q with no %q attribute", entry.DN, b.config.GroupNameAttribute)
				continue
			}

			groupNames[normaliseDN(entry.DN)] = b.config.GroupPrefix + name
		}
	}

	return groupNames, nil
}

// searchUsers returns a mapping of lower cased username -> group names, using
// the memberOf attribute of each user filtered down to the known groups.
func (b *backend) searchUsers(c conn, groupNames map[string]string) (map[string][]string, error) {
	mapping := make(map[string][]string)

	for _, base := range b.config.UserSearchBases {
		req := goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, 0, false, b.config.UserFilter,
			[]string{b.config.UsernameAttribute, memberOfAttribute}, nil)

		res, err := c.SearchWithPaging(req, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to search users in %q: %s", base, err)
		}

		for _, entry := range res.Entries {
			username := entry.GetAttributeValue(b.config.UsernameAttribute)
			if username == "" {
				klog.V(4).Infof("skipping user %q with no %q attribute", entry.DN, b.config.UsernameAttribute)
				continue
			}

			groups := make([]string, 0)
			for _, dn := range entry.GetAttributeValues(memberOfAttribute) {
				if name, ok := groupNames[normaliseDN(dn)]; ok {
					groups = append(groups, name)
				}
			}

			mapping[strings.ToLower(username)] = groups
		}
	}

	return mapping, nil
}

// connect dials the configured URLs in order, returning the first connection
// that can be established and bound.
func (b *backend) connect() (conn, error) {
	var errs []string

	for _, url := range b.config.URLs {
		c, err := b.dial(url)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", url, err))
			continue
		}

		if b.config.StartTLS {
			if err := c.StartTLS(b.tlsConfig); err != nil {
				c.Close()
				errs = append(errs, fmt.Sprintf("%s: StartTLS failed: %s", url, err))
				continue
			}
		}

		// An empty bind DN leaves the connection anonymous.
		if b.config.BindDN != "" {
			if err := c.Bind(b.config.BindDN, b.bindPassword); err != nil {
				c.Close()
				errs = append(errs, fmt.Sprintf("%s: bind failed: %s", url, err))
				continue
			}
		}

		return c, nil
	}

	return nil, fmt.Errorf("unable to connect to any server [%s]", strings.Join(errs, ", "))
}

func (b *backend) dialLDAP(url string) (conn, error) {
	return goldap.DialURL(url, goldap.DialWithTLSConfig(b.tlsConfig))
}

func tlsConfigFor(config *BackendConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipTLSVerify,
	}

	if config.CAFile == "" {
		return tlsConfig, nil
	}

	ca, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("backend %q: failed to read caFile %q: %s", config.Name, config.CAFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("backend %q: no certificates found in caFile %q", config.Name, config.CAFile)
	}
	tlsConfig.RootCAs = pool

	return tlsConfig, nil
}

// normaliseDN makes DNs comparable across the group and memberOf attributes,
// which are not guaranteed to agree on case or spacing.
func normaliseDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}

	return strings.ToLower(strings.Join(parts, ","))
}
