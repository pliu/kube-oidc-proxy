// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"k8s.io/klog/v2"
)

func (d *UserDirectory) runRefresh() {
	ticker := time.NewTicker(d.resolver.config.RefreshInterval.Duration())
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			term := d.leadership()
			if term == nil || term.Err() != nil {
				continue
			}
			if err := d.refreshWhileLeader(term); err != nil && term.Err() == nil && d.ctx.Err() == nil {
				klog.Errorf("LDAP cached-user refresh: %v", err)
			}
		}
	}
}

// Leadership loss or replica shutdown cancels scheduling and waiting, while
// shared lookups retain the independent lifetime owned by resolve. The cycle
// derives from the replica context so that shutdown cancels it at the same
// moment as shared lookups, which also derive from it; otherwise a lookup
// failing on shutdown could be reported before the cycle saw cancellation.
// Leadership loss does not end shared lookups, so it is linked asynchronously.
func (d *UserDirectory) refreshWhileLeader(term context.Context) error {
	cycle, cancel := context.WithCancel(d.ctx)
	defer cancel()
	stop := context.AfterFunc(term, cancel)
	defer stop()
	return d.RefreshCached(cycle)
}

// RefreshCached snapshots only known users and refreshes them in batches of
// refreshBatchSize, one batch after another. Every user's
// committed record is read with one List before any LDAP search. A batch finds
// its users with one search per backend and user search base, and resolves
// each group they hold once. Each record still commits independently; a
// failed user retains its previous entry while other users can advance.
func (d *UserDirectory) RefreshCached(ctx context.Context) error {
	start := time.Now()
	d.mu.RLock()
	keys := make([]string, 0, len(d.users))
	for _, cell := range d.users {
		if !cell.deleted && cell.entry.Record != nil && cell.entry.Invalid == nil {
			keys = append(keys, cell.entry.Record.Username)
		}
	}
	d.mu.RUnlock()
	// Sorted so that a cycle's batches do not depend on map order.
	slices.Sort(keys)
	listed, err := d.listCommitted(ctx)
	if err != nil {
		// Every user's refresh failed on the read it depends on.
		for range keys {
			d.failed(failureKubernetes, err)
		}
		lastRefreshSuccess.Set(0)
		return fmt.Errorf("list cached users: %w", err)
	}
	var failures []error
	for batch := range slices.Chunk(keys, d.resolver.config.RefreshBatchSize) {
		if ctx.Err() != nil {
			break
		}
		for _, result := range d.refreshBatch(ctx, batch, listed) {
			if result.err != nil {
				failures = append(failures, result.err)
			}
		}
	}
	if ctx.Err() != nil {
		failures = append(failures, ctx.Err())
	} else {
		fullRefreshDuration.Observe(time.Since(start).Seconds())
	}
	if len(failures) > 0 {
		lastRefreshSuccess.Set(0)
	} else {
		lastRefreshSuccess.Set(1)
	}
	return errors.Join(failures...)
}
