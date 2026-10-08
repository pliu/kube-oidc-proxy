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
// lookup. Existing calls can still be joined and memory hits remain available.
var ErrLookupCapacity = errors.New("LDAP lookup capacity exhausted")

type userCall struct {
	done  chan struct{}
	entry cache.UserEntry
	err   error
}

// Resolve returns cache hits without external I/O. Waiter cancellation does
// not cancel shared work, which has its own timeout and shutdown context.
func (d *UserDirectory) Resolve(ctx context.Context, username string) ([]string, bool, error) {
	key := usernameKey(username, d.resolver.config.UsernamePrefix)
	entry, err := d.resolve(ctx, key, false)
	if err != nil {
		return nil, false, err
	}
	return append([]string{}, entry.Record.Groups...), entry.Record.Found, nil
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
		// The map bounds the entire lookup, including persistence, and permits
		// same-user waiters to join even while capacity is exhausted.
		if len(d.calls) >= d.resolver.config.LookupConcurrency {
			d.callsMu.Unlock()
			return cache.UserEntry{}, ErrLookupCapacity
		}
		call = &userCall{done: make(chan struct{})}
		d.calls[key] = call
		go func() {
			work, cancel := context.WithTimeout(d.ctx, d.resolver.config.LookupTimeout.Duration())
			defer cancel()
			call.entry, call.err = d.lookup(work, key, refresh)
			d.callsMu.Lock()
			delete(d.calls, key)
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

func (d *UserDirectory) lookup(ctx context.Context, key string, refresh bool) (cache.UserEntry, error) {
	// Capture the committed version BEFORE LDAP, even when watch delivery lags.
	previous, err := d.store.Get(ctx, key)
	if err != nil && !errors.Is(err, cache.ErrNotFound) {
		return cache.UserEntry{}, err
	}
	if err == nil && previous.Invalid == nil && !refresh {
		d.apply(previous, false)
		return d.committed(key)
	}
	groups, found, err := d.resolver.searchUser(ctx, key)
	if err != nil {
		return cache.UserEntry{}, err
	}
	// key is already the canonical identity; it must not be canonicalized again.
	record, err := cache.NewUserRecord(key, found, groups, d.resolver.fingerprint, time.Now())
	if err != nil {
		return cache.UserEntry{}, err
	}
	changed := previous.Record == nil || previous.Record.Found != found || !slices.Equal(previous.Record.Groups, record.Groups)
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
