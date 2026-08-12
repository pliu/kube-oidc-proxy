// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	Users map[string][]string `json:"users"`
}

// SnapshotBackend is what one backend contributed to a persisted mapping. How
// long it took is deliberately not kept: it describes the refresh that built
// the snapshot, not the mapping being read back.
type SnapshotBackend struct {
	Name   string `json:"name"`
	Users  int    `json:"users"`
	Groups int    `json:"groups"`
}

// persist writes the mapping to the configured store. A store that cannot be
// written to is logged and otherwise ignored: the mapping in memory is good,
// and failing the refresh over it would throw away a mapping that requests can
// be served from right now.
func (d *Directory) persist(mapping map[string][]string, groups int, builtAt time.Time, backends []BackendStats) {
	if d.cache == nil {
		return
	}

	persisted := make([]SnapshotBackend, 0, len(backends))
	for _, b := range backends {
		persisted = append(persisted, SnapshotBackend{Name: b.Name, Users: b.Users, Groups: b.Groups})
	}

	data, err := json.Marshal(&Snapshot{
		Version:     snapshotVersion,
		MappingHash: d.mappingHash,
		BuiltAt:     builtAt,
		Groups:      groups,
		Backends:    persisted,
		Users:       mapping,
	})
	if err != nil {
		klog.Errorf("failed to encode the LDAP mapping to persist to %s: %s", d.cache, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cacheTimeout)
	defer cancel()

	if err := d.cache.Save(ctx, data); err != nil {
		klog.Errorf("failed to persist the LDAP mapping to %s: %s", d.cache, err)
		return
	}

	klog.V(4).Infof("persisted LDAP mapping of %d users to %s", len(mapping), d.cache)
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

	snapshot, err := d.decodeSnapshot(data)
	if err != nil {
		klog.Errorf("ignoring the LDAP mapping persisted in %s: %s", d.cache, err)
		return false
	}

	d.seedCounts(snapshot.Backends)

	mapping := snapshot.Users
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

func (d *Directory) decodeSnapshot(data []byte) (*Snapshot, error) {
	snapshot := new(Snapshot)
	if err := json.Unmarshal(data, snapshot); err != nil {
		return nil, fmt.Errorf("failed to decode it: %s", err)
	}

	if snapshot.Version != snapshotVersion {
		return nil, fmt.Errorf("it is version %d, and this proxy writes version %d",
			snapshot.Version, snapshotVersion)
	}

	if snapshot.MappingHash != d.mappingHash {
		return nil, errors.New("it was built from a different backend configuration")
	}

	if snapshot.Users == nil {
		return nil, errors.New("it holds no users")
	}

	// A mapping that predates the configured maximum age describes group
	// memberships too old to be worth impersonating users with.
	if maxAge := d.maxCacheAge(); maxAge > 0 {
		if age := time.Since(snapshot.BuiltAt); age > maxAge {
			return nil, fmt.Errorf("it was built %s ago, over the configured maxAge of %s",
				age.Truncate(time.Second), maxAge)
		}
	}

	return snapshot, nil
}

func (d *Directory) maxCacheAge() time.Duration {
	if d.config.Cache == nil {
		return 0
	}

	return d.config.Cache.MaxAge.Duration()
}
