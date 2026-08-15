// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

const (
	// snapshotVersion is bumped whenever a persisted mapping stops being
	// readable by the code that reads it back. A snapshot of another version
	// is discarded.
	snapshotVersion = 1

	// cacheTimeout bounds a read or write of the persisted mapping, so that an
	// unresponsive store cannot hold up a refresh indefinitely.
	cacheTimeout = time.Second * 30
)

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

	// Said here as well as by the role never reaching a rebuild, because "one
	// writer" is the property the whole split rests on: a reader that wrote
	// would be overwriting the builder with a mapping it got from the builder,
	// and nothing downstream would notice.
	if !d.config.Role.Persists() {
		return nil
	}

	persisted := make([]SnapshotBackend, 0, len(backends))
	for _, b := range backends {
		persisted = append(persisted, SnapshotBackend{Name: b.Name, Users: b.Users, Groups: b.Groups})
	}

	table, users := internMapping(mapping)

	snapshot := &Snapshot{
		Version:     snapshotVersion,
		MappingHash: d.mappingHash,
		BuiltAt:     builtAt,
		Groups:      groups,
		Backends:    persisted,
		GroupTable:  table,
		Users:       users,
	}

	// A refresh that rebuilt the mapping the store already holds has nothing to
	// add to it. Most refreshes are that: group memberships change far less
	// often than they are looked at, which is why the mapping is worth building
	// ahead of time at all. There is no partial write either - the whole
	// mapping goes out every time it goes out at all - so on a directory that
	// is not changing this is the difference between rewriting megabytes every
	// refresh interval and writing nothing.
	hash := snapshot.contentHash()

	ctx, cancel := context.WithTimeout(context.Background(), cacheTimeout)
	defer cancel()

	if d.storeHolds(ctx, hash) && !d.held().ageing(builtAt, d.maxCacheAge()) {
		klog.V(4).Infof("LDAP mapping of %d users is the one already persisted to %s, leaving it",
			len(mapping), d.cache)

		return nil
	}

	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("failed to encode the mapping to persist to %s: %s", d.cache, err)
	}

	if err := d.cache.Save(ctx, data, hash); err != nil {
		return fmt.Errorf("failed to persist the mapping to %s: %s", d.cache, err)
	}

	// Recorded only once the write is through, so that a store which failed is
	// written to again by the next refresh rather than being taken for holding
	// a mapping it never received.
	d.persisted.Store(&persistedSnapshot{hash: hash, builtAt: builtAt})

	klog.V(4).Infof("persisted LDAP mapping of %d users to %s", len(mapping), d.cache)

	return nil
}

// storeHolds reports whether the store is already holding the mapping with
// this fingerprint.
//
// A store that can be asked is asked, rather than taken at the word of what
// this proxy last wrote to it. What this proxy wrote is only the same thing
// while it is the only one writing, and a store is a shared object: another
// proxy sharing it can have written over the top at any point, and believing
// otherwise would leave the two disagreeing for as long as neither mapping
// changed - which is to say, indefinitely.
//
// A store that cannot say, or that fails to, is written to. Writing a mapping
// the store already holds costs a write; skipping one it does not hold loses
// the mapping.
func (d *Directory) storeHolds(ctx context.Context, hash string) bool {
	fingerprinter, ok := d.cache.(cache.Fingerprinter)
	if !ok {
		return hash == d.held().hash
	}

	held, err := fingerprinter.Fingerprint(ctx)
	if errors.Is(err, cache.ErrNotFound) {
		return false
	}
	if err != nil {
		klog.V(2).Infof("failed to check which LDAP mapping %s holds, persisting anyway: %s", d.cache, err)
		return false
	}

	return held != "" && held == hash
}

// persistedSnapshot is what the store is taken to hold: the fingerprint of the
// mapping it holds, and the build time recorded with it.
//
// The fingerprint is the one this proxy wrote, on a proxy that writes; the one
// the store reported, on a proxy that took the mapping from a store that can
// report it; and one computed from the payload otherwise. It is compared
// against what the store says it holds, so which of those it is matters: see
// loadHolding.
//
// Written only by the refresh path, which Refresh serialises, and by restore
// before the first refresh.
type persistedSnapshot struct {
	hash    string
	builtAt time.Time
}

// held is what the store is taken to be holding, never nil.
func (d *Directory) held() persistedSnapshot {
	if persisted := d.persisted.Load(); persisted != nil {
		return *persisted
	}

	return persistedSnapshot{}
}

// ageing reports whether a mapping that has not changed should be written again
// anyway, to carry the build time recorded with it forwards.
//
// Only maxAge makes that time matter, and it is measured by the proxy that
// reads the snapshot back rather than by this one. A mapping confirmed against
// the directories every refresh interval for a week is still recorded as a week
// old if it was never rewritten in that time, and would be thrown away at
// exactly the restart it exists for. Rewriting it once it is halfway to being
// rejected keeps it servable without going back to writing on every refresh.
func (p persistedSnapshot) ageing(now time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false
	}

	return now.Sub(p.builtAt) >= maxAge/2
}

// contentHash fingerprints the mapping a snapshot carries, together with what
// decides whether this proxy can load it back at all - the format version and
// the configuration it was built from - so that a refresh which rebuilt the
// mapping already in the store has nothing to write.
//
// The per backend counts are deliberately left out. They describe the searches
// that produced the mapping rather than the mapping itself, and the group count
// is every group under the search bases, including ones no user in them belongs
// to. Hashing them makes a directory change that alters nobody's groups -
// creating an empty group, say - rewrite the whole store for a mapping that is
// byte for byte the one it already holds. Which backends contributed is still
// covered, so a snapshot written before the counts were recorded at all is not
// mistaken for one that carries them and left without them for good.
//
// Leaving them out cannot hide a change that matters. The counts are read back
// only to prime the guard on a backend that has stopped returning anything,
// which asks whether they have fallen to zero rather than what they are; and a
// backend whose users fell to zero has lost its entries from the mapping, which
// is hashed, so that write happens anyway.
//
// The interned form it runs over is already canonical - internMapping sorts the
// table, and the groups of a user are sorted before they are interned - so the
// same mapping always fingerprints the same way. Usernames are walked in order
// because a map is not, and every string is written with its length, so that a
// group name holding a separator cannot pass for two fields.
func (s *Snapshot) contentHash() string {
	h := sha256.New()

	buf := appendHashed(nil, s.MappingHash)
	buf = appendCounts(buf, s.Version, len(s.Backends), len(s.GroupTable), len(s.Users))
	h.Write(buf)

	for _, b := range s.Backends {
		buf = appendHashed(buf[:0], b.Name)
		h.Write(buf)
	}

	for _, group := range s.GroupTable {
		buf = appendHashed(buf[:0], group)
		h.Write(buf)
	}

	usernames := make([]string, 0, len(s.Users))
	for username := range s.Users {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)

	for _, username := range usernames {
		indices := s.Users[username]

		buf = appendHashed(buf[:0], username)
		buf = appendCounts(buf, indices...)
		h.Write(buf)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// appendHashed writes a string length prefixed, so that no combination of
// values can be arranged into the same bytes as a different one.
func appendHashed(buf []byte, s string) []byte {
	buf = strconv.AppendInt(buf, int64(len(s)), 10)
	buf = append(buf, ':')

	return append(buf, s...)
}

// appendCounts writes numbers separated from each other and terminated, for the
// same reason.
func appendCounts(buf []byte, counts ...int) []byte {
	for _, count := range counts {
		buf = strconv.AppendInt(buf, int64(count), 10)
		buf = append(buf, ',')
	}

	return append(buf, ';')
}

// restore installs the persisted mapping, if there is a usable one, and
// reports whether it did. It runs before the first refresh, so that a proxy
// that starts while every directory is down has something to serve.
func (d *Directory) restore() bool {
	if d.cache == nil {
		return false
	}

	if err := d.load(); err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			klog.V(2).Infof("no LDAP mapping persisted in %s yet", d.cache)
		} else {
			klog.Errorf("ignoring the LDAP mapping persisted in %s: %s", d.cache, err)
		}

		return false
	}

	return true
}

// load installs the mapping the store is holding. It is how a proxy that does
// not build one gets everything it serves, and how one that does gets what it
// serves until its first rebuild finishes.
//
// The mapping is fingerprinted from the snapshot that was read back, which is
// the only answer available to a caller holding nothing but the payload, and
// the right one for a store that keeps no fingerprint of its own.
func (d *Directory) load() error {
	return d.loadHolding("")
}

// loadHolding installs the mapping the store is holding, recording it under the
// fingerprint the store reported for it rather than under one computed here.
//
// The two are the same string only while every proxy sharing the store computes
// it the same way, and that is a property of the binary rather than of the
// mapping: contentHash covers the snapshot format and what can be served, so a
// change to it - which has happened, without the format itself moving - leaves a
// reader that recomputed disagreeing with the builder that wrote. Every
// comparison a reader makes is against what the store reports, both the
// fingerprint it is polled for and the one a watch delivers, so recording
// anything else has it fetch and reinstall the whole mapping on every
// notification and every resync until the builder next writes.
//
// An empty fingerprint means the caller has none to offer, and the snapshot is
// fingerprinted here instead.
func (d *Directory) loadHolding(fingerprint string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cacheTimeout)
	defer cancel()

	data, err := d.cache.Load(ctx)
	if err != nil {
		return err
	}

	snapshot, mapping, err := d.decodeSnapshot(data)
	if err != nil {
		return err
	}

	d.seedCounts(snapshot.Backends)

	if fingerprint == "" {
		fingerprint = snapshot.contentHash()
	}

	// The store is already holding this, so neither a rebuild that produces the
	// same mapping nor a poll that finds the same fingerprint has any reason to
	// go back to it.
	d.persisted.Store(&persistedSnapshot{hash: fingerprint, builtAt: snapshot.BuiltAt})

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

	return nil
}

// reload installs the mapping the store is holding, if it is not already the
// one being served. It is what a reader does in place of a rebuild.
//
// The check is made against the fingerprint the store reports, which for a
// Secret is read without the mapping attached, so the ordinary case - a poll
// that finds nothing new - costs one request for the metadata of one object
// rather than a copy of the whole mapping. That fingerprint is what the mapping
// is then recorded under, so that the next poll compares like with like.
//
// It is read before the mapping rather than after, so a publication landing
// between the two is recorded under the fingerprint of the one before it: the
// next poll finds a mismatch and fetches a mapping it already has, which costs a
// request. The other order loses the publication instead - the reader would
// record a fingerprint newer than the payload it read back, and go on serving
// the older mapping until something else changed.
func (d *Directory) reload() error {
	fingerprinter, ok := d.cache.(cache.Fingerprinter)
	if !ok {
		return d.load()
	}

	ctx, cancel := context.WithTimeout(context.Background(), cacheTimeout)
	defer cancel()

	held, err := fingerprinter.Fingerprint(ctx)
	if err != nil {
		return err
	}

	if held != "" && held == d.held().hash && d.HasMapping() {
		klog.V(4).Infof("LDAP mapping in %s is the one being served", d.cache)
		return nil
	}

	return d.loadHolding(held)
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

	// A reader holds no backends, so it has no configuration of its own to
	// compare this against. The builder that wrote the snapshot is the
	// authority on whether it describes the directories it was built from -
	// it is the only thing that ever reached them.
	if d.config.Role.Builds() && snapshot.MappingHash != d.mappingHash {
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

		// Sorted so that one mapping has one interned form, whatever order the
		// groups of a user arrived in. Callers sort them first anyway, but that
		// makes this canonical by convention rather than by construction, and
		// the fingerprint taken over it is what decides whether a mapping is
		// written and whether every proxy serving it fetches it again.
		sort.Ints(indices)

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
