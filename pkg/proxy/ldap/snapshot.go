// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

// snapshotVersion is bumped whenever a persisted mapping stops being readable
// by the code that reads it back. A snapshot of another version is discarded.
const snapshotVersion = 1

// Snapshot is a built mapping as it is persisted.
type Snapshot struct {
	Version int `json:"version"`

	// MappingHash identifies the configuration the mapping was built from. A
	// snapshot built from a different set of search bases, filters or prefixes
	// describes a directory layout the proxy is no longer configured for, so
	// it is discarded rather than served.
	MappingHash string `json:"mappingHash"`

	BuiltAt time.Time `json:"builtAt"`
	Groups  int       `json:"groups"`

	// Backends records what each backend contributed, so that the guard
	// against a backend that has stopped returning anything survives a
	// restart - which is the event the persisted mapping exists for. A
	// snapshot written before this was recorded simply leaves the guard
	// unprimed until the first refresh.
	Backends []SnapshotBackend `json:"backends,omitempty"`

	// GroupTable holds each distinct group name once, and Users holds indices
	// into it rather than the names themselves. A directory is mostly users
	// sharing the same few thousand groups, so spelling every name out in
	// every entry it appears in is the bulk of the payload - and the stores
	// this is written to are not unbounded. Interning takes a mapping of
	// 25,000 users at ten groups each from around 2.1MiB compressed to
	// 0.6MiB, and cuts the work of decoding it at startup by as much.
	GroupTable []string `json:"groupTable"`

	// Users maps each username to their groups, as indices into GroupTable.
	Users map[string][]int `json:"users"`
}

// SnapshotBackend is what one backend contributed to a persisted mapping. How
// long it took is deliberately not kept: it describes the refresh that built
// the snapshot, not the mapping being read back.
type SnapshotBackend struct {
	Name   string `json:"name"`
	Users  int    `json:"users"`
	Groups int    `json:"groups"`
}

// persist writes the mapping to the configured store. It runs before the
// mapping is served, so that what is persisted is never older than what is
// being served.
//
// A store that cannot be written to therefore fails the rebuild, rather than
// being logged and carried on from. Serving a mapping that could not be
// persisted is what lets a restart go backwards: the proxy would come back up,
// find the previous mapping in the store, and serve that instead - and if the
// directories are unreachable by then, it has no way of getting forwards
// again. Keeping the previous mapping, which is the one in the store, at least
// leaves the two agreeing.
func (d *Directory) persist(mapping map[string][]string, groups int, builtAt time.Time, backends []BackendStats) error {
	if d.cache == nil {
		return nil
	}

	persisted := make([]SnapshotBackend, 0, len(backends))
	for _, b := range backends {
		persisted = append(persisted, SnapshotBackend{Name: b.Name, Users: b.Users, Groups: b.Groups})
	}

	table, users := internMapping(mapping)

	data, err := json.Marshal(&Snapshot{
		Version:     snapshotVersion,
		MappingHash: d.mappingHash,
		BuiltAt:     builtAt,
		Groups:      groups,
		Backends:    persisted,
		GroupTable:  table,
		Users:       users,
	})
	if err != nil {
		return fmt.Errorf("failed to encode the mapping to persist to %s: %s", d.cache, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cacheTimeout)
	defer cancel()

	if err := d.cache.Save(ctx, data); err != nil {
		return fmt.Errorf("failed to persist the mapping to %s: %s", d.cache, err)
	}

	klog.V(4).Infof("persisted LDAP mapping of %d users to %s", len(mapping), d.cache)

	return nil
}

// restore installs the persisted mapping, if there is a usable one, and
// reports whether it did. It runs before the first refresh, so that a proxy
// that starts while every directory is down has something to serve.
func (d *Directory) restore() bool {
	if d.cache == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), cacheTimeout)
	defer cancel()

	data, err := d.cache.Load(ctx)
	if errors.Is(err, cache.ErrNotFound) {
		klog.V(2).Infof("no LDAP mapping persisted in %s yet", d.cache)
		return false
	}
	if err != nil {
		klog.Errorf("failed to load the LDAP mapping persisted in %s: %s", d.cache, err)
		return false
	}

	snapshot, mapping, err := d.decodeSnapshot(data)
	if err != nil {
		klog.Errorf("ignoring the LDAP mapping persisted in %s: %s", d.cache, err)
		return false
	}

	d.seedCounts(snapshot.Backends)

	finalise(mapping)

	d.mapping.Store(&mapping)
	d.stats.Store(&Stats{
		Users:       len(mapping),
		Groups:      snapshot.Groups,
		LastRefresh: snapshot.BuiltAt,
		Source:      SourceCache,
	})

	klog.Infof("loaded LDAP mapping of %d users built %s ago from %s",
		len(mapping), time.Since(snapshot.BuiltAt).Truncate(time.Second), d.cache)

	return true
}

// seedCounts primes the per backend counts from a restored snapshot, so that a
// backend which was returning users before a restart is still held to that
// after it. Without this the guard would be unprimed on exactly the startup
// where a directory has quietly stopped answering, and the degraded mapping
// would be accepted and persisted over the good one.
//
// Backend names are covered by the configuration hash, so a snapshot that got
// this far names the configured backends. Matching on the name anyway keeps a
// hand written or truncated snapshot from priming the wrong backend.
func (d *Directory) seedCounts(backends []SnapshotBackend) {
	if len(backends) == 0 {
		return
	}

	byName := make(map[string]*backend, len(d.backends))
	for _, b := range d.backends {
		byName[b.config.Name] = b
	}

	for _, snapshot := range backends {
		if b, ok := byName[snapshot.Name]; ok {
			b.lastUsers, b.lastGroups = snapshot.Users, snapshot.Groups
		}
	}
}

// decodeSnapshot returns a persisted snapshot along with the mapping held in
// it, or an error describing why it is not one this proxy can serve.
func (d *Directory) decodeSnapshot(data []byte) (*Snapshot, map[string][]string, error) {
	snapshot := new(Snapshot)
	if err := json.Unmarshal(data, snapshot); err != nil {
		return nil, nil, fmt.Errorf("failed to decode it: %s", err)
	}

	if snapshot.Version != snapshotVersion {
		return nil, nil, fmt.Errorf("it is version %d, and this proxy writes version %d",
			snapshot.Version, snapshotVersion)
	}

	if snapshot.MappingHash != d.mappingHash {
		return nil, nil, errors.New("it was built from a different backend configuration")
	}

	if snapshot.Users == nil {
		return nil, nil, errors.New("it holds no users")
	}

	// A mapping that predates the configured maximum age describes group
	// memberships too old to be worth impersonating users with.
	if maxAge := d.maxCacheAge(); maxAge > 0 {
		if age := time.Since(snapshot.BuiltAt); age > maxAge {
			return nil, nil, fmt.Errorf("it was built %s ago, over the configured maxAge of %s",
				age.Truncate(time.Second), maxAge)
		}
	}

	mapping, err := snapshot.mapping()
	if err != nil {
		return nil, nil, err
	}

	return snapshot, mapping, nil
}

// internMapping splits a mapping into the table of distinct group names and
// the per user indices into it that are persisted in its place.
//
// The table is sorted, so that a mapping that has not changed encodes to the
// same bytes however the map was walked, and so that names sharing a prefix -
// which group DNs from one directory largely do - sit next to each other for
// the compressor.
func internMapping(mapping map[string][]string) ([]string, map[string][]int) {
	index := make(map[string]int)
	for _, groups := range mapping {
		for _, group := range groups {
			index[group] = 0
		}
	}

	table := make([]string, 0, len(index))
	for group := range index {
		table = append(table, group)
	}
	sort.Strings(table)

	for i, group := range table {
		index[group] = i
	}

	users := make(map[string][]int, len(mapping))
	for username, groups := range mapping {
		indices := make([]int, 0, len(groups))
		for _, group := range groups {
			indices = append(indices, index[group])
		}

		users[username] = indices
	}

	return table, users
}

// mapping resolves the interned form back into the username to groups mapping
// that is served. An index the table does not hold means the snapshot was
// truncated or written by hand, and none of it can be trusted to name the
// groups a user actually holds.
func (s *Snapshot) mapping() (map[string][]string, error) {
	mapping := make(map[string][]string, len(s.Users))

	for username, indices := range s.Users {
		groups := make([]string, 0, len(indices))
		for _, i := range indices {
			if i < 0 || i >= len(s.GroupTable) {
				return nil, fmt.Errorf("user %q holds group %d, outside the table of %d groups it was written with",
					username, i, len(s.GroupTable))
			}

			groups = append(groups, s.GroupTable[i])
		}

		mapping[username] = groups
	}

	return mapping, nil
}

func (d *Directory) maxCacheAge() time.Duration {
	if d.config.Cache == nil {
		return 0
	}

	return d.config.Cache.MaxAge.Duration()
}
