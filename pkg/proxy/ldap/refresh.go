// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

// Run builds the initial mapping and then keeps it refreshed until stopCh is
// closed.
//
// The initial refresh is synchronous: starting to serve requests with an empty
// mapping would silently strip every user of their groups. A persisted mapping
// is loaded first so that it can stand in if that refresh fails, and only when
// there is no mapping to fall back on does a failure stop the proxy starting.
func (d *Directory) Run(stopCh <-chan struct{}) error {
	if !d.config.Role.Builds() {
		return d.runReader(stopCh)
	}

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

// runReader serves the mapping a builder published, and keeps it up to date by
// polling the store until stopCh is closed. It never reaches a directory.
//
// A reader that finds nothing published yet starts anyway and reports itself
// unready, rather than refusing to start as a builder with nothing to serve
// does. The two are not the same situation: a builder with no mapping has
// exhausted everything it can do about it, while a reader is waiting on a
// builder that is very likely part way through its first sweep. Crash looping
// through that is noise, and the readiness gate keeps it out of a Service in
// the meantime just as effectively.
func (d *Directory) runReader(stopCh <-chan struct{}) error {
	if err := d.load(); err != nil {
		// Anything other than an empty store says this proxy cannot read the
		// store at all - it is misconfigured, or not permitted to - and it
		// would sit unready for good rather than converge. Fail where somebody
		// is watching.
		if !errors.Is(err, cache.ErrNotFound) {
			return fmt.Errorf("failed to load the LDAP mapping published in %s: %s", d.cache, err)
		}

		klog.Warningf("no LDAP mapping published in %s yet, so this proxy will not report itself "+
			"ready until a builder has written one", d.cache)
	} else {
		// A reader that starts with a mapping already published, and then sees
		// it never change, would otherwise never pass through the path that
		// reports success and would look permanently failed.
		lastRefreshSuccess.Set(1)
	}

	// Configuration allows a reader only a store that can report its own
	// changes, so this is a guard rather than a case anybody reaches: a reader
	// that could not be told about a new mapping would serve the one it
	// started with until it was restarted.
	watcher, ok := d.cache.(cache.Watcher)
	if !ok {
		return fmt.Errorf("%s cannot report when the mapping it holds changes, "+
			"so the %q role has no way of picking up a newly published one", d.cache, d.config.Role)
	}

	return d.watchStore(watcher, stopCh)
}

// watchStore picks up a newly published mapping as it lands, rather than at the
// next poll, so that a rebuild the builder was asked for reaches the proxies
// serving it in about as long as it takes to write.
//
// What the store reports is the fingerprint of the mapping it now holds, so a
// change that turns out to be the mapping already being served - a resync, or
// something else writing the same thing - costs nothing but the comparison.
func (d *Directory) watchStore(watcher cache.Watcher, stopCh <-chan struct{}) error {
	published := func(fingerprint string) {
		if fingerprint == d.held().hash && d.HasMapping() {
			return
		}

		// Through Refresh rather than straight into load, so that a mapping
		// landing while one is already being read does not have two goroutines
		// installing mappings over each other.
		if err := d.Refresh(); err != nil {
			klog.Errorf("failed to load the LDAP mapping published in %s: %s", d.cache, err)
		}
	}

	if err := watcher.Watch(stopCh, published); err != nil {
		return fmt.Errorf("failed to watch %s for published LDAP mappings: %s", d.cache, err)
	}

	klog.V(2).Infof("watching %s for LDAP mappings published by the builder", d.cache)

	return nil
}

// refreshCall is one rebuild, along with the result every caller waiting on it
// is given.
type refreshCall struct {
	done    chan struct{}
	err     error
	pending bool
}

// Refresh rebuilds the user -> group mapping from every backend and atomically
// swaps it in. The previous mapping is left in place if the rebuild fails.
//
// A caller arriving while a rebuild is running joins it and takes its result
// rather than queueing another. Merely serialising builders would turn a burst
// of requests to the refresh endpoint into that many complete rebuilds run
// back to back, each searching every directory again for an answer the one
// before it already had - and by default any authenticated user may ask for
// one. A reader is different: a caller joining an older store load marks one
// follow-up reload pending, because it may be carrying a newer publication.
func (d *Directory) Refresh() error {
	d.refreshMu.Lock()

	if call := d.inflight; call != nil {
		// A reader notification carries information newer than whatever load
		// was already in flight. Joining that load is not enough: it may have
		// captured the old store contents before the publication arrived. Mark
		// one more reload pending so the notification cannot be lost.
		if !d.config.Role.Builds() {
			call.pending = true
		}
		d.refreshMu.Unlock()

		<-call.done

		return call.err
	}

	call := &refreshCall{done: make(chan struct{})}
	d.inflight = call

	d.refreshMu.Unlock()

	for {
		call.err = d.refresh()

		d.refreshMu.Lock()
		if call.pending {
			call.pending = false
			d.refreshMu.Unlock()
			continue
		}

		// Cleared before the waiters are released, so that a caller arriving as
		// this one finishes starts a rebuild of its own rather than being handed
		// the result of one that is already over.
		d.inflight = nil
		d.refreshMu.Unlock()
		break
	}

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
	// A reader has no directories to rebuild from, so the most it can do when
	// asked is go and see whether the builder has published anything newer.
	// Refreshing the mapping everything is serving means asking the builder,
	// which is why the refresh endpoint is routed to it.
	if !d.config.Role.Builds() {
		if err := d.reload(); err != nil {
			// A reader does not rebuild, so what the gauge reports for one is
			// whether it is still able to pick up what the builder publishes.
			// Left unset it would sit at zero for the life of every reader,
			// and an alert on it would fire on all of them for good.
			lastRefreshSuccess.Set(0)

			return fmt.Errorf("failed to load the LDAP mapping published in %s: %s", d.cache, err)
		}

		lastRefreshSuccess.Set(1)

		return nil
	}

	// Held across the directory read as well as the publication. Serialising
	// only persist-and-swap would allow an older single-user search to land
	// after this rebuild and regress that user in the builder and every reader.
	release := d.lockUpdate()
	defer release()

	start := time.Now()

	built, err := d.build()
	if err != nil {
		// A failed rebuild is not an outage - the previous mapping keeps
		// serving - so nothing else surfaces that group changes have stopped
		// being picked up.
		lastRefreshSuccess.Set(0)

		return err
	}

	if err := d.persist(built.mapping, built.groups, start, built.stats); err != nil {
		lastRefreshSuccess.Set(0)

		return err
	}

	// The per-backend baselines describe the mapping that was accepted, not
	// merely a search that happened to finish. A later backend or the store can
	// still fail after an earlier backend was searched, in which case the old
	// mapping and its baselines must remain authoritative together.
	for i, stats := range built.stats {
		d.backends[i].lastUsers, d.backends[i].lastGroups = stats.Users, stats.Groups
		d.backends[i].lastGroupNames.Store(&built.groupNames[i])
	}

	// Measured over the persisting as well as the searching, since a rebuild
	// is not finished until the mapping it built is safe to serve.
	took := time.Since(start)

	lastRefreshSuccess.Set(1)
	refreshDuration.Observe(took.Seconds())

	d.mapping.Store(&built.mapping)

	d.stats.Store(&Stats{
		Users:       len(built.mapping),
		Groups:      built.groups,
		LastRefresh: start,
		Duration:    took.String(),
		Source:      SourceDirectory,
		Backends:    built.stats,
	})

	klog.V(2).Infof("refreshed LDAP mapping from %d backends: %d users, %d groups (%s)",
		len(d.backends), len(built.mapping), built.groups, took)

	return nil
}

// lockUpdate serialises every directory read that can replace some or all of
// the mapping. The apply itself is not enough to serialise: a single-user
// refresh can finish an older search after a newer full rebuild has landed,
// and would otherwise publish its stale result over the rebuild.
func (d *Directory) lockUpdate() func() {
	<-d.updateGate
	return func() { d.updateGate <- struct{}{} }
}

// lockUpdateCtx is lockUpdate that gives up when ctx is cancelled, so a
// single-user refresh can stop waiting if the caller has gone away.
func (d *Directory) lockUpdateCtx(ctx context.Context) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.updateGate:
		return func() { d.updateGate <- struct{}{} }, nil
	}
}
