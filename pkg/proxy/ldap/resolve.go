// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const unchangedWriteInterval = time.Hour

// ErrLookupCapacity means this replica has no room for another distinct-user
// lookup of the kind asked for. Request lookups are limited by
// lookupConcurrency, and refresh to one batch at a time, separately. Existing calls of either kind can still be joined and memory
// hits remain available.
var ErrLookupCapacity = errors.New("LDAP lookup capacity exhausted")

// userCall is one user's lookup in flight, shared by everyone waiting on it.
type userCall struct {
	done chan struct{}
	lookupResult
}

// Resolve returns cache hits without external I/O. Waiter cancellation does
// not cancel shared work, which has its own timeout and shutdown context.
func (d *UserDirectory) Resolve(ctx context.Context, username string) ([]string, error) {
	key := usernameKey(username, d.resolver.config.UsernamePrefix)
	entry, err := d.resolve(ctx, key)
	if err != nil {
		return nil, err
	}
	return append([]string{}, entry.Record.Groups...), nil
}

// resolve looks up one user for a request.
func (d *UserDirectory) resolve(ctx context.Context, key string) (cache.UserEntry, error) {
	if err := ctx.Err(); err != nil {
		return cache.UserEntry{}, err
	}
	if entry, ok := d.cached(key); ok {
		return entry, nil
	}
	d.callsMu.Lock()
	call := d.calls[key]
	if call == nil {
		if err := d.ctx.Err(); err != nil {
			d.callsMu.Unlock()
			return cache.UserEntry{}, err
		}
		// Admission happens before allocating shared work or performing I/O.
		// A slot is held for the entire lookup, including persistence, and
		// same-user waiters can join even while capacity is exhausted.
		if d.lookups >= d.resolver.config.LookupConcurrency {
			d.callsMu.Unlock()
			return cache.UserEntry{}, ErrLookupCapacity
		}
		d.lookups++
		call = &userCall{done: make(chan struct{})}
		d.calls[key] = call
		go func() {
			work, cancel := context.WithTimeout(d.ctx, d.resolver.config.LookupTimeout.Duration())
			defer cancel()
			call.entry, call.err = d.lookup(work, key)
			d.callsMu.Lock()
			delete(d.calls, key)
			d.lookups--
			close(call.done)
			d.callsMu.Unlock()
		}()
	}
	d.callsMu.Unlock()
	return awaitCall(ctx, call)
}

func awaitCall(ctx context.Context, call *userCall) (cache.UserEntry, error) {
	result := awaitResult(ctx, call)
	return result.entry, result.err
}

func awaitResult(ctx context.Context, call *userCall) lookupResult {
	select {
	case <-ctx.Done():
		return lookupResult{err: ctx.Err()}
	case <-call.done:
		return call.lookupResult
	}
}

// lookupResult is the outcome of refreshing one user of a batch.
type lookupResult struct {
	entry cache.UserEntry
	err   error
}

// refreshBatch refreshes keys together, returning one result per key in order.
//
// Only one batch runs at a time, admitted outside lookupConcurrency, and it searches
// each backend for all of its users at once. Every user still gets a shared
// call of their own, so a request for one of them joins the batch rather than
// looking them up again, and a user a request is already looking up is joined
// rather than searched in the batch. Each record commits independently.
//
// listed holds the committed records of the cycle by ConfigMap name, from
// listCommitted; without it, each user's record is read on its own.
func (d *UserDirectory) refreshBatch(ctx context.Context, keys []string, listed map[string]cache.UserEntry) []lookupResult {
	results := make([]lookupResult, len(keys))
	if err := ctx.Err(); err != nil {
		for i := range results {
			results[i].err = err
		}
		return results
	}

	calls := make([]*userCall, len(keys))
	var owned []string
	var ownedCalls []*userCall
	d.callsMu.Lock()
	admit := d.ctx.Err()
	if admit == nil && d.refreshing {
		admit = ErrLookupCapacity
	}
	for i, key := range keys {
		if call := d.calls[key]; call != nil {
			calls[i] = call
			continue
		}
		if admit != nil {
			results[i].err = admit
			continue
		}
		call := &userCall{done: make(chan struct{})}
		d.calls[key] = call
		calls[i] = call
		owned = append(owned, key)
		ownedCalls = append(ownedCalls, call)
	}
	if len(owned) > 0 {
		// Admission happens before allocating shared work or performing I/O,
		// and the slot is held until every user of the batch has committed.
		d.refreshing = true
		go func() {
			found := d.lookupBatch(owned, listed)
			d.callsMu.Lock()
			for i, call := range ownedCalls {
				call.lookupResult = found[i]
				delete(d.calls, owned[i])
				close(call.done)
			}
			d.refreshing = false
			d.callsMu.Unlock()
		}()
	}
	d.callsMu.Unlock()

	for i, call := range calls {
		if call == nil {
			continue
		}
		results[i] = awaitResult(ctx, call)
	}
	return results
}

// failed counts a failed refresh of one user against what the step under way
// depended on, and returns err. A lookup cut short by the replica shutting
// down did not fail.
func (d *UserDirectory) failed(source string, err error) error {
	if err != nil && d.ctx.Err() == nil {
		userRefreshFailures.WithLabelValues(source).Inc()
	}
	return err
}

// previous reads the committed record of key, if there is one.
//
// It is read BEFORE LDAP, even when watch delivery lags, and is the version a
// lookup writes against. The refresh cycle reads every user's record with one
// List at its start instead; see listCommitted.
//
// A refresh could take previous from memory instead, saving this read for
// every cached user in every cycle. As the version to write against that
// would be safe: one from memory is never newer than the stored one, so a
// record committed since still conflicts and still wins, at the cost of a
// discarded lookup whenever the watch is behind. As the record to compare
// against it is not: if memory holds X, another replica has since stored Y
// and the directory answers X, the write in commit is skipped as unchanged and
// Y, which the directory no longer agrees with, is served by every replica
// until the next cycle. Memory would only do if the unchanged-write skip
// went with it, so that every refresh writes, which trades a read per user
// for a write per user and a watch event on every replica. Keep the read
// unless that trade, or the staleness, is preferred.
func (d *UserDirectory) previous(ctx context.Context, key string) (cache.UserEntry, error) {
	previous, err := d.store.Get(ctx, key)
	if err != nil && !errors.Is(err, cache.ErrNotFound) {
		return cache.UserEntry{}, d.failed(failureKubernetes, err)
	}
	return previous, nil
}

// listCommitted reads the committed record of every user with one List, by
// ConfigMap name, for a refresh cycle to compare and write against instead of
// reading each user's record on its own.
//
// The list is read before any of the cycle's LDAP searches, but a batch late in
// the cycle uses a record read minutes before its search, rather than moments
// before as previous does. That is accepted:
//
//   - A record committed since carries a newer version, so writing against the
//     listed one conflicts, and the committed record is reloaded and kept.
//   - The staleness previous warns of needs another replica to have stored a
//     record during the cycle, which happens only on a miss and so only for a
//     record that was itself just looked up, and the directory to have changed
//     back since. The next cycle corrects it.
func (d *UserDirectory) listCommitted(ctx context.Context) (map[string]cache.UserEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, d.resolver.config.LookupTimeout.Duration())
	defer cancel()
	list, err := d.store.List(ctx)
	if err != nil {
		return nil, err
	}
	listed := make(map[string]cache.UserEntry, len(list.Entries))
	for _, entry := range list.Entries {
		listed[entry.Name] = entry
	}
	return listed, nil
}

// listedPrevious returns the listed record of key as Get would: none if no
// ConfigMap is listed under its name, and one holding another user's record as
// Invalid, with its version, so that it is replaced rather than served.
func listedPrevious(listed map[string]cache.UserEntry, key string) (cache.UserEntry, error) {
	name, err := cache.UserConfigMapName(key)
	if err != nil {
		return cache.UserEntry{}, err
	}
	entry, ok := listed[name]
	if !ok {
		return cache.UserEntry{}, nil
	}
	if entry.Record != nil && entry.Record.Username != key {
		entry.Invalid = fmt.Errorf("ConfigMap %q holds the record of %q", name, entry.Record.Username)
		entry.Record = nil
	}
	return entry, nil
}

// lookup resolves a request's miss: from Kubernetes when another replica has
// already stored the user, and otherwise from LDAP.
func (d *UserDirectory) lookup(ctx context.Context, key string) (cache.UserEntry, error) {
	previous, err := d.previous(ctx, key)
	if err != nil {
		return cache.UserEntry{}, err
	}
	if previous.Record != nil && previous.Invalid == nil {
		d.apply(previous, false)
		return d.served(key)
	}
	groups, err := d.resolver.searchUser(ctx, key)
	if err != nil {
		return cache.UserEntry{}, d.failed(failureLDAP, err)
	}
	return d.commit(ctx, key, previous, groups)
}

// lookupBatch refreshes keys from LDAP, searching each backend for all of them
// at once, and commits each user on their own. A user whose read, search or
// write fails keeps their previous record while the others advance. Each
// user's previous record comes from listed when it is given.
//
// Each user's read and write, and the batch's search, has its own
// lookupTimeout, so a batch is not held to the deadline of a single lookup
// while it waits on a rate-limited Kubernetes client for many users.
func (d *UserDirectory) lookupBatch(keys []string, listed map[string]cache.UserEntry) []lookupResult {
	timeout := d.resolver.config.LookupTimeout.Duration()
	results := make([]lookupResult, len(keys))
	previous := make([]cache.UserEntry, len(keys))
	var search []string
	var searched []int
	for i, key := range keys {
		var err error
		if listed != nil {
			previous[i], err = listedPrevious(listed, key)
		} else {
			ctx, cancel := context.WithTimeout(d.ctx, timeout)
			previous[i], err = d.previous(ctx, key)
			cancel()
		}
		if err != nil {
			results[i].err = err
			continue
		}
		search = append(search, key)
		searched = append(searched, i)
	}
	if len(search) == 0 {
		return results
	}

	ctx, cancel := context.WithTimeout(d.ctx, timeout)
	found, err := d.resolver.searchUsers(ctx, search, true)
	cancel()
	for j, i := range searched {
		switch {
		case err != nil:
			results[i].err = d.failed(failureLDAP, err)
		case found[j].err != nil:
			results[i].err = d.failed(failureLDAP, found[j].err)
		default:
			ctx, cancel := context.WithTimeout(d.ctx, timeout)
			results[i].entry, results[i].err = d.commit(ctx, keys[i], previous[i], found[j].groups)
			cancel()
		}
	}
	return results
}

// commit persists what LDAP answered for key against the previous record,
// skipping a write that would change nothing but a recent timestamp.
func (d *UserDirectory) commit(ctx context.Context, key string, previous cache.UserEntry, groups []string) (cache.UserEntry, error) {
	// key is already the canonical identity; it must not be canonicalized again.
	// A record that fails validation does so for what the directory returned.
	record, err := cache.NewUserRecord(key, groups, d.resolver.fingerprint, time.Now())
	if err != nil {
		return cache.UserEntry{}, d.failed(failureLDAP, err)
	}
	changed := previous.Record == nil || !slices.Equal(previous.Record.Groups, record.Groups)
	if !changed && record.LastSuccessfulLookup.Sub(previous.Record.LastSuccessfulLookup) < unchangedWriteInterval {
		d.apply(previous, false)
		return d.served(key)
	}
	committed, err := d.store.Upsert(ctx, record, previous.ResourceVersion)
	if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
		// Never retry an old LDAP answer over another writer's committed record.
		committed, err = d.store.Get(ctx, key)
	}
	if err != nil {
		return cache.UserEntry{}, d.failed(failureKubernetes, err)
	}
	if committed.Invalid != nil || committed.Record == nil {
		return cache.UserEntry{}, d.failed(failureKubernetes,
			fmt.Errorf("committed cache record is invalid: %v", committed.Invalid))
	}
	d.apply(committed, false)
	// Watch may already have delivered an even newer record.
	return d.served(key)
}

// served returns the record memory now holds for key, counting its absence
// against Kubernetes.
func (d *UserDirectory) served(key string) (cache.UserEntry, error) {
	entry, err := d.committed(key)
	return entry, d.failed(failureKubernetes, err)
}

func (d *UserDirectory) CanRefresh(username string) bool { return d.resolver.CanRefresh(username) }
func (d *UserDirectory) committed(key string) (cache.UserEntry, error) {
	if current, ok := d.cached(key); ok {
		return current, nil
	}
	return cache.UserEntry{}, fmt.Errorf("cache record changed or was deleted while resolving %q", key)
}
