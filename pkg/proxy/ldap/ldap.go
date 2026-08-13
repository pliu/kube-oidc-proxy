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
	"net"
	"os"
	"sort"
	"strconv"
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

	// rangeOption is the attribute option a directory answers with when it has
	// returned only part of a multi valued attribute. Active Directory caps
	// memberOf at MaxValRange, 1500 values by default, and substitutes
	// "memberOf;range=0-1499" for the attribute that was asked for.
	rangeOption = "range="

	// maxRangeRequests bounds the follow up searches made to collect a
	// truncated attribute, so that a directory which never advances the window
	// cannot hold a refresh here indefinitely.
	maxRangeRequests = 1000

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

// duplicateUserError reports two entries of one backend claiming one username.
// It is a type of its own so that the condition can be reported as a metric,
// which is what an operator needs to notice a directory that needs cleaning up
// rather than one that is merely unreachable.
type duplicateUserError struct {
	username string
	first    string
	second   string
}

func (e *duplicateUserError) Error() string {
	return fmt.Sprintf("%q is held by both %q and %q, so the groups to give them are ambiguous",
		e.username, e.first, e.second)
}

// conn is the subset of *goldap.Conn used by a backend, so that the search
// behaviour can be exercised without a live directory.
type conn interface {
	StartTLS(*tls.Config) error
	Bind(username, password string) error
	SearchWithPaging(req *goldap.SearchRequest, pagingSize uint32) (*goldap.SearchResult, error)
	Search(req *goldap.SearchRequest) (*goldap.SearchResult, error)
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

	// Published from here rather than at init, so that a proxy running without
	// augmentation configured reports no series at all. Every backend starts
	// with a series of its own, so that "no duplicates" is a zero rather than
	// an absence an alert cannot tell from a backend that never ran.
	registerMetrics()
	for _, b := range backends {
		backendDuplicateUsers.WithLabelValues(b.config.Name).Set(0)
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
	// Saying so out loud, because the cost is paid at the worst moment: a pod
	// that restarts while a directory is unreachable - a rollout, a drain, an
	// eviction, an OOM kill - has nothing to serve and will not start at all.
	// Persistence is what turns that outage into a stale mapping.
	if d.cache == nil {
		klog.Warning("no LDAP mapping cache is configured, so the proxy will refuse to start if a " +
			"directory is unreachable at startup, and will keep doing so until one answers")
	}

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

// refreshCall is one rebuild, along with the result every caller waiting on it
// is given.
type refreshCall struct {
	done chan struct{}
	err  error
}

// Refresh rebuilds the user -> group mapping from every backend and atomically
// swaps it in. The previous mapping is left in place if the rebuild fails.
//
// A caller arriving while a rebuild is running joins it and takes its result
// rather than queueing another. Merely serialising them would turn a burst of
// requests to the refresh endpoint into that many complete rebuilds run back
// to back, each searching every directory again for an answer the one before
// it already had - and by default any authenticated user may ask for one.
func (d *Directory) Refresh() error {
	d.refreshMu.Lock()

	if call := d.inflight; call != nil {
		d.refreshMu.Unlock()

		<-call.done

		return call.err
	}

	call := &refreshCall{done: make(chan struct{})}
	d.inflight = call

	d.refreshMu.Unlock()

	call.err = d.refresh()

	// Cleared before the waiters are released, so that a caller arriving as
	// this one finishes starts a rebuild of its own rather than being handed
	// the result of one that is already over.
	d.refreshMu.Lock()
	d.inflight = nil
	d.refreshMu.Unlock()

	close(call.done)

	return call.err
}

// refresh does the rebuild itself. Only the caller that claimed the rebuild
// runs it, so it needs no locking of its own.
//
// The mapping is persisted before it is served, so that what is in the store is
// never older than what requests are being answered from. The other order lets
// a restart go backwards in time: a proxy that served a mapping it had not yet
// persisted, and then died, would come back up and serve the older one it finds
// in the store - and if the directories are unreachable by then, it cannot get
// forwards again.
func (d *Directory) refresh() error {
	start := time.Now()

	mapping, groups, backendStats, err := d.build()
	if err != nil {
		// A failed rebuild is not an outage - the previous mapping keeps
		// serving - so nothing else surfaces that group changes have stopped
		// being picked up.
		lastRefreshSuccess.Set(0)

		return err
	}

	if err := d.persist(mapping, groups, start, backendStats); err != nil {
		lastRefreshSuccess.Set(0)

		return err
	}

	// Measured over the persisting as well as the searching, since a rebuild
	// is not finished until the mapping it built is safe to serve.
	took := time.Since(start)

	lastRefreshSuccess.Set(1)
	refreshDuration.Observe(took.Seconds())

	d.mapping.Store(&mapping)
	d.stats.Store(&Stats{
		Users:       len(mapping),
		Groups:      groups,
		LastRefresh: start,
		Duration:    took.String(),
		Source:      SourceDirectory,
		Backends:    backendStats,
	})

	klog.V(2).Infof("refreshed LDAP mapping from %d backends: %d users, %d groups (%s)",
		len(d.backends), len(mapping), groups, took)

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

		took := time.Since(start)
		backendRefreshDuration.WithLabelValues(b.config.Name).Observe(took.Seconds())

		stats = append(stats, BackendStats{
			Name:     b.config.Name,
			Users:    len(built),
			Groups:   builtGroups,
			Duration: took.String(),
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
	// A directory that accepts a connection and then stops answering would
	// otherwise hold a refresh here for as long as the process runs: go-ldap
	// waits for a response on a channel with no deadline of its own, so
	// closing the connection under it is the only way back out.
	w := newWatchdog(b.config.Timeout.Duration())
	defer w.stop()

	c, err := b.connect(w)
	if err != nil {
		return nil, 0, w.wrap(err)
	}
	defer c.Close()

	// Only groups that live under one of the configured search bases are
	// pulled, so the mapping is restricted to the intended part of the tree.
	groupNames, err := b.searchGroups(c)
	if err != nil {
		return nil, 0, w.wrap(err)
	}

	mapping, err := b.searchUsers(c, groupNames)
	if err != nil {
		// A directory holding one username twice needs cleaning up, so it is
		// worth telling apart from a directory that is merely unreachable.
		var duplicate *duplicateUserError
		if errors.As(err, &duplicate) {
			backendDuplicateUsers.WithLabelValues(b.config.Name).Set(1)
		}

		return nil, 0, w.wrap(err)
	}

	backendDuplicateUsers.WithLabelValues(b.config.Name).Set(0)

	return mapping, len(groupNames), nil
}

// watchdog closes a connection that a backend has not finished with in time.
//
// go-ldap reads a response off a channel that nothing else ever writes to if
// the directory goes quiet, and neither Conn.SetTimeout nor the request time
// limit reaches that: the first bounds the delivery of a response that did
// arrive, the second is enforced by a server that is still listening. Closing
// the connection is what unblocks the read, so that is what this does.
type watchdog struct {
	timeout time.Duration
	timer   *time.Timer

	mu sync.Mutex
	// c is the connection to close, once there is one to close.
	c conn
	// fired records that the timeout expired, so that whatever error the
	// closed connection produces can be reported as the timeout it is.
	fired bool
}

// timeLimit is the timeout as the seconds a search request carries, so that a
// directory which is still listening gives up on its own and answers with a
// result code, rather than being cut off mid sentence by the watchdog. It is
// rounded up, since a limit of zero is what the protocol uses for no limit.
func (b *backend) timeLimit() int {
	seconds := int((b.config.Timeout.Duration() + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}

	return seconds
}

func newWatchdog(timeout time.Duration) *watchdog {
	w := &watchdog{timeout: timeout}
	w.timer = time.AfterFunc(timeout, w.fire)

	return w
}

// watch hands the watchdog the connection to close, closing it immediately if
// the timeout has already expired.
func (w *watchdog) watch(c conn) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.c = c

	if w.fired {
		c.Close()
	}
}

// forget drops a connection the backend has closed itself, so that a later
// timeout cannot close a connection this backend no longer owns.
func (w *watchdog) forget() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.c = nil
}

func (w *watchdog) fire() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.fired = true

	if w.c != nil {
		w.c.Close()
	}
}

func (w *watchdog) stop() {
	w.timer.Stop()
}

// wrap reports an error as the timeout that caused it, when it was. What
// go-ldap returns from a connection closed under it says nothing about why.
func (w *watchdog) wrap(err error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err == nil || !w.fired {
		return err
	}

	return fmt.Errorf("timed out after %s: %s", w.timeout, err)
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
			0, b.timeLimit(), false, b.config.GroupFilter, []string{b.config.GroupNameAttribute}, nil)

		res, err := c.SearchWithPaging(req, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to search groups in %q: %s", base, err)
		}

		for _, entry := range res.Entries {
			name := attributeValue(entry, b.config.GroupNameAttribute)
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
//
// Two entries of one directory that claim the same username fail the rebuild.
// Which of them a request should be authorized as is genuinely ambiguous, and
// resolving it by taking whichever the directory happened to return last would
// hand a user groups that depend on search order.
func (b *backend) searchUsers(c conn, groupNames map[string]string) (map[string][]string, error) {
	mapping := make(map[string][]string)

	// claimedBy holds the DN that a username was found on, so that two entries
	// claiming one identity can be told apart from one entry returned twice by
	// search bases that overlap.
	claimedBy := make(map[string]string)

	for _, base := range b.config.UserSearchBases {
		req := goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, b.timeLimit(), false, b.config.UserFilter,
			[]string{b.config.UsernameAttribute, memberOfAttribute}, nil)

		res, err := c.SearchWithPaging(req, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to search users in %q: %s", base, err)
		}

		for _, entry := range res.Entries {
			username := attributeValue(entry, b.config.UsernameAttribute)
			if username == "" {
				klog.V(4).Infof("skipping user %q with no %q attribute", entry.DN, b.config.UsernameAttribute)
				continue
			}

			key := strings.ToLower(username)

			if claimed, ok := claimedBy[key]; ok {
				// One entry returned again because the search bases overlap
				// carries the same groups either way, so it is not ambiguous.
				if normaliseDN(claimed) != normaliseDN(entry.DN) {
					return nil, &duplicateUserError{username: username, first: claimed, second: entry.DN}
				}

				continue
			}

			claimedBy[key] = entry.DN

			dns, err := b.memberOfDNs(c, entry)
			if err != nil {
				return nil, err
			}

			groups := make([]string, 0)
			for _, dn := range dns {
				if name, ok := groupNames[normaliseDN(dn)]; ok {
					groups = append(groups, name)
				}
			}

			mapping[key] = groups
		}
	}

	return mapping, nil
}

// connect dials the configured URLs in order, returning the first connection
// that can be established and bound.
//
// Each connection is handed to the watchdog as soon as it exists, since a
// directory that accepts the connection and then never answers the bind hangs
// just as thoroughly as one that never answers a search.
func (b *backend) connect(w *watchdog) (conn, error) {
	var errs []string

	for _, url := range b.config.URLs {
		c, err := b.dial(url)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", url, err))
			continue
		}

		w.watch(c)

		if b.config.StartTLS {
			if err := c.StartTLS(b.tlsConfig); err != nil {
				c.Close()
				w.forget()
				errs = append(errs, fmt.Sprintf("%s: StartTLS failed: %s", url, err))
				continue
			}
		}

		// An empty bind DN leaves the connection anonymous.
		if b.config.BindDN != "" {
			if err := c.Bind(b.config.BindDN, b.bindPassword); err != nil {
				c.Close()
				w.forget()
				errs = append(errs, fmt.Sprintf("%s: bind failed: %s", url, err))
				continue
			}
		}

		return c, nil
	}

	return nil, fmt.Errorf("unable to connect to any server [%s]", strings.Join(errs, ", "))
}

func (b *backend) dialLDAP(url string) (conn, error) {
	// The watchdog cannot close a connection that does not exist yet, so the
	// dial carries its own bound. go-ldap otherwise applies a package level
	// default of 60s, which no configuration can move.
	dialer := &net.Dialer{Timeout: b.config.Timeout.Duration()}

	return goldap.DialURL(url, goldap.DialWithTLSConfig(b.tlsConfig), goldap.DialWithDialer(dialer))
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

// attributeValues returns the values of the named attribute of an entry, along
// with any options the directory attached to it.
//
// An attribute description is matched by name rather than compared as a whole,
// because a directory is free to answer with a description that is not the one
// that was asked for. Active Directory substitutes "memberOf;range=0-1499" for
// a truncated "memberOf", and directories differ on the case they echo back -
// 389 Directory Server, and so FreeIPA, answers in the case its schema
// defines. Entry.GetAttributeValues compares the description exactly, so it
// silently finds nothing in either case.
func attributeValues(entry *goldap.Entry, name string) (values []string, options string, found bool) {
	for _, attribute := range entry.Attributes {
		base, options := splitAttributeDescription(attribute.Name)
		if strings.EqualFold(base, name) {
			return attribute.Values, options, true
		}
	}

	return nil, "", false
}

// attributeValue returns the first value of the named attribute, or "".
func attributeValue(entry *goldap.Entry, name string) string {
	values, _, _ := attributeValues(entry, name)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// splitAttributeDescription splits an attribute description into its name and
// its options: the "memberOf" and "range=0-1499" of "memberOf;range=0-1499".
func splitAttributeDescription(description string) (name, options string) {
	if i := strings.IndexByte(description, ';'); i >= 0 {
		return description[:i], description[i+1:]
	}

	return description, ""
}

// memberOfChunk is the memberOf values of an entry, together with where the
// directory truncated them.
type memberOfChunk struct {
	dns []string

	// next is the index the values continue from, or -1 when the directory
	// returned all of them.
	next int
}

// memberOfFrom reads the memberOf values of an entry, honouring the range
// option a directory truncates them with.
func memberOfFrom(entry *goldap.Entry) (memberOfChunk, error) {
	values, options, found := attributeValues(entry, memberOfAttribute)
	if !found {
		// An entry that is a member of nothing, or one asked for a window
		// past the end of its memberOf.
		return memberOfChunk{next: -1}, nil
	}

	next, err := parseRangeOption(options)
	if err != nil {
		return memberOfChunk{}, fmt.Errorf("entry %q: %s", entry.DN, err)
	}

	return memberOfChunk{dns: values, next: next}, nil
}

// parseRangeOption returns the index the values of a ranged attribute continue
// from, or -1 when the attribute is not ranged or this is the last window of
// it. The option is "range=0-1499" for a truncated attribute and
// "range=3000-*" for the window that completes it.
func parseRangeOption(options string) (int, error) {
	for _, option := range strings.Split(options, ";") {
		if len(option) < len(rangeOption) || !strings.EqualFold(option[:len(rangeOption)], rangeOption) {
			continue
		}

		bounds := option[len(rangeOption):]

		i := strings.IndexByte(bounds, '-')
		if i < 0 {
			return 0, fmt.Errorf("malformed range option %q", option)
		}

		// The window that completes the attribute ends in "*" rather than in
		// the index of its last value.
		last := bounds[i+1:]
		if last == "*" {
			return -1, nil
		}

		end, err := strconv.Atoi(last)
		if err != nil {
			return 0, fmt.Errorf("malformed range option %q", option)
		}

		return end + 1, nil
	}

	return -1, nil
}

// memberOfDNs returns every group DN of an entry, collecting the rest of them
// a window at a time if the directory truncated the attribute.
//
// Active Directory caps memberOf at MaxValRange, 1500 values by default, and
// expects a client that wants the rest to ask for them explicitly. Ignoring
// that leaves the users in the most groups - who tend to be the ones with the
// most access - holding no groups at all, since the truncated attribute comes
// back under a description that does not match the one asked for.
//
// 389 Directory Server, and so FreeIPA, returns every value and never takes
// this path.
func (b *backend) memberOfDNs(c conn, entry *goldap.Entry) ([]string, error) {
	chunk, err := memberOfFrom(entry)
	if err != nil {
		return nil, err
	}

	dns := chunk.dns

	for requests := 0; chunk.next >= 0; requests++ {
		if requests == maxRangeRequests {
			return nil, fmt.Errorf("gave up collecting the %s of %q after %d requests",
				memberOfAttribute, entry.DN, maxRangeRequests)
		}

		from := chunk.next

		chunk, err = b.searchMemberOfRange(c, entry.DN, from)
		if err != nil {
			return nil, err
		}

		dns = append(dns, chunk.dns...)

		// A directory that answers a window without moving past it would
		// otherwise be asked the same question until the bound above is hit.
		if chunk.next >= 0 && chunk.next <= from {
			return nil, fmt.Errorf("directory did not advance the %s range of %q past %d",
				memberOfAttribute, entry.DN, from)
		}
	}

	return dns, nil
}

// searchMemberOfRange reads the memberOf values of one entry from the given
// index onwards.
func (b *backend) searchMemberOfRange(c conn, dn string, from int) (memberOfChunk, error) {
	attribute := fmt.Sprintf("%s;%s%d-*", memberOfAttribute, rangeOption, from)

	req := goldap.NewSearchRequest(dn, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, b.timeLimit(), false, "(objectClass=*)", []string{attribute}, nil)

	res, err := c.Search(req)
	if err != nil {
		return memberOfChunk{}, fmt.Errorf("failed to read %q of %q: %s", attribute, dn, err)
	}

	if len(res.Entries) != 1 {
		return memberOfChunk{}, fmt.Errorf("failed to read %q of %q: expected one entry, got %d",
			attribute, dn, len(res.Entries))
	}

	return memberOfFrom(res.Entries[0])
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
