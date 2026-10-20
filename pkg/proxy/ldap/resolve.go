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
// lookup of the kind asked for. Request lookups and refresh lookups have
// separate limits. Existing calls of either kind can still be joined and memory
// hits remain available.
var ErrLookupCapacity = errors.New("LDAP lookup capacity exhausted")

type userCall struct {
	done  chan struct{}
	entry cache.UserEntry
	err   error
}

// Resolve returns cache hits without external I/O. Waiter cancellation does
// not cancel shared work, which has its own timeout and shutdown context.
func (d *UserDirectory) Resolve(ctx context.Context, username string) ([]string, error) {
	key := usernameKey(username, d.resolver.config.UsernamePrefix)
	entry, err := d.resolve(ctx, key, false)
	if err != nil {
		return nil, err
	}
	return append([]string{}, entry.Record.Groups...), nil
}

func (d *UserDirectory) resolve(ctx context.Context, key string, refresh bool) (cache.UserEntry, error) {
	if err := ctx.Err(); err != nil {
		return cache.UserEntry{}, err
	}
	if !refresh {
		if entry, ok := d.cached(key); ok {
			return entry, nil
		}
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
		// same-user waiters can join even while capacity is exhausted. Refresh
		// has its own limit, so a cycle cannot starve request lookups.
		active, limit := &d.lookups, d.resolver.config.LookupConcurrency
		if refresh {
			active, limit = &d.refreshes, d.resolver.config.RefreshConcurrency
		}
		if *active >= limit {
			d.callsMu.Unlock()
			return cache.UserEntry{}, ErrLookupCapacity
		}
		*active++
		call = &userCall{done: make(chan struct{})}
		d.calls[key] = call
		go func() {
			work, cancel := context.WithTimeout(d.ctx, d.resolver.config.LookupTimeout.Duration())
			defer cancel()
			call.entry, call.err = d.lookup(work, key, refresh)
			d.callsMu.Lock()
			delete(d.calls, key)
			*active--
			close(call.done)
			d.callsMu.Unlock()
		}()
	}
	d.callsMu.Unlock()
	select {
	case <-ctx.Done():
		return cache.UserEntry{}, ctx.Err()
	case <-call.done:
		return call.entry, call.err
	}
}

func (d *UserDirectory) lookup(ctx context.Context, key string, refresh bool) (_ cache.UserEntry, err error) {
	// source is what the step under way depends on, and so what a failure of
	// it is counted against. A lookup cut short by the replica shutting down
	// did not fail.
	source := failureKubernetes
	defer func() {
		if err != nil && d.ctx.Err() == nil {
			userRefreshFailures.WithLabelValues(source).Inc()
		}
	}()

	// Capture the committed version BEFORE LDAP, even when watch delivery lags.
	//
	// A refresh could take previous from memory instead, saving this read for
	// every cached user in every cycle. As the version to write against that
	// would be safe: one from memory is never newer than the stored one, so a
	// record committed since still conflicts and still wins, at the cost of a
	// discarded lookup whenever the watch is behind. As the record to compare
	// against it is not: if memory holds X, another replica has since stored Y
	// and the directory answers X, the write below is skipped as unchanged and
	// Y, which the directory no longer agrees with, is served by every replica
	// until the next cycle. Memory would only do if the unchanged-write skip
	// went with it, so that every refresh writes, which trades a read per user
	// for a write per user and a watch event on every replica. Keep the read
	// unless that trade, or the staleness, is preferred.
	previous, err := d.store.Get(ctx, key)
	if err != nil && !errors.Is(err, cache.ErrNotFound) {
		return cache.UserEntry{}, err
	}
	if err == nil && previous.Invalid == nil && !refresh {
		d.apply(previous, false)
		return d.committed(key)
	}
	source = failureLDAP
	groups, err := d.resolver.searchUser(ctx, key, refresh)
	if err != nil {
		return cache.UserEntry{}, err
	}
	// key is already the canonical identity; it must not be canonicalized again.
	// A record that fails validation does so for what the directory returned.
	record, err := cache.NewUserRecord(key, groups, d.resolver.fingerprint, time.Now())
	if err != nil {
		return cache.UserEntry{}, err
	}
	source = failureKubernetes
	changed := previous.Record == nil || !slices.Equal(previous.Record.Groups, record.Groups)
	if !changed && record.LastSuccessfulLookup.Sub(previous.Record.LastSuccessfulLookup) < unchangedWriteInterval {
		d.apply(previous, false)
		return d.committed(key)
	}
	committed, err := d.store.Upsert(ctx, record, previous.ResourceVersion)
	if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
		// Never retry an old LDAP answer over another writer's committed record.
		committed, err = d.store.Get(ctx, key)
	}
	if err != nil {
		return cache.UserEntry{}, err
	}
	if committed.Invalid != nil || committed.Record == nil {
		return cache.UserEntry{}, fmt.Errorf("committed cache record is invalid: %v", committed.Invalid)
	}
	d.apply(committed, false)
	// Watch may already have delivered an even newer record.
	return d.committed(key)
}

func (d *UserDirectory) CanRefresh(username string) bool { return d.resolver.CanRefresh(username) }
func (d *UserDirectory) committed(key string) (cache.UserEntry, error) {
	if current, ok := d.cached(key); ok {
		return current, nil
	}
	return cache.UserEntry{}, fmt.Errorf("cache record changed or was deleted while resolving %q", key)
}
