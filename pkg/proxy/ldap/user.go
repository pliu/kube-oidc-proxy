// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/klog/v2"
)

// ErrNoMapping is returned by RefreshUser before there is a mapping to update.
// Nothing serves requests in that state, so it is only reachable by a caller
// that got to the endpoint before the first rebuild finished.
var ErrNoMapping = errors.New("no LDAP mapping has been built yet")

// UserStats describes what refreshing a single user did.
//
// It reports how many groups the user holds rather than which, because by
// default any authenticated user may call the endpoint: naming them would turn
// it into a way of reading the group membership of anybody whose username can
// be guessed.
type UserStats struct {
	User  string `json:"user"`
	Found bool   `json:"found"`

	// Groups is how many groups the user now holds.
	Groups int `json:"groups"`

	// Changed reports whether this made any difference. A refresh that found
	// what was already being served leaves the store alone.
	Changed bool `json:"changed"`

	Duration string `json:"duration"`
}

// RefreshUser re-searches the directories for one user and, when what it found
// differs from what is being served, persists and swaps in a mapping carrying
// the change.
//
// A user the directory gained since the last rebuild otherwise holds no groups
// until the next one, which on a large directory is most of a refresh interval
// away. Rebuilding everybody to pick that up means searching every directory
// in full; this searches for the one user who changed.
//
// It is the whole mapping that gets written out for that one user, since there
// is no partial write - but that is what makes the change outlive a restart
// and reach the readers of a builder, which is the only way it reaches the
// proxies actually taking user traffic. A rebuild of everybody would write
// exactly the same amount and search the entire directory to get there.
func (d *Directory) RefreshUser(ctx context.Context, username string) (*UserStats, error) {
	if !d.config.Role.Builds() {
		return nil, fmt.Errorf("the %q role never reaches a directory, so it cannot refresh a user", d.config.Role)
	}

	if !d.HasMapping() {
		return nil, ErrNoMapping
	}

	// Checked before waiting behind another update, and again after it. go-ldap
	// takes no context, so a search that has started runs to the backend timeout
	// whether or not the caller is still there.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Cover the search as well as the persist-and-swap. If only the latter were
	// serialised, this search could capture an old membership, wait for a newer
	// full rebuild to land, and then publish the old membership over it. On a
	// builder that regression would be persisted and sent to every reader.
	release, err := d.lockUpdateCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	// Cancellation and the gate becoming available can happen together, in
	// which case select may choose either. Do not start the directory search if
	// the caller was already gone when the wait ended.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	start := time.Now()
	key := usernameKey(username, d.config.UsernamePrefix)

	groups, found, err := d.searchUser(key)
	if err != nil {
		return nil, err
	}

	changed, err := d.applyUser(key, groups, found)
	if err != nil {
		return nil, err
	}

	stats := &UserStats{
		User:     username,
		Found:    found,
		Groups:   len(groups),
		Changed:  changed,
		Duration: time.Since(start).String(),
	}

	klog.V(2).Infof("refreshed %q from the directories: found=%t, %d groups, changed=%t (%s)",
		username, found, len(groups), changed, stats.Duration)

	return stats, nil
}

// applyUser folds one searched user into the mapping being served, persisting
// it first so that the store is never older than what requests are answered
// from - the same order a rebuild uses, and for the same reason.
func (d *Directory) applyUser(key string, groups []string, found bool) (bool, error) {
	// RefreshUser holds updateGate across the search, persist and swap, so the
	// mapping cannot move underneath this copy and a burst of refreshes of one
	// user costs one write rather than one each: whichever gets here second
	// finds nothing left to change.

	mapping := *d.mapping.Load()

	current, held := mapping[key]
	if held == found && equalGroups(current, groups) {
		return false, nil
	}

	stats := *d.stats.Load()

	next := make(map[string][]string, len(mapping)+1)
	for username, groups := range mapping {
		next[username] = groups
	}

	if found {
		next[key] = groups
	} else {
		// The directories no longer hold a user the mapping does, so serving
		// them their old groups is serving an entry the last rebuild would
		// have dropped.
		delete(next, key)
	}

	// The mapping is mostly as old as the rebuild that built it, so that is
	// what it is persisted as. Claiming the age of this one user for all of it
	// would let a stale mapping pass the maxAge check on a restart.
	if err := d.persist(next, stats.Groups, stats.LastRefresh, stats.Backends); err != nil {
		return false, err
	}

	d.mapping.Store(&next)

	stats.Users = len(next)
	d.stats.Store(&stats)

	return true, nil
}

// equalGroups reports whether two group lists hold the same names. Both are
// sorted by the time they get here, so this is a comparison rather than a set
// difference.
func equalGroups(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
