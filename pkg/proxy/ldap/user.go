// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"k8s.io/klog/v2"
)

// maxGroupDiscoveries bounds the groups one refresh of a user will look up
// individually, so that a mapping far enough out of date cannot turn refreshing
// one user into a search per group they hold.
const maxGroupDiscoveries = 100

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

	// Checked before the directories are searched rather than after, since
	// that is the only point at which the answer changes anything: go-ldap
	// takes no context, so a search that has started runs to the backend
	// timeout whether or not the caller is still there.
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
	// Held across the persist as well as the swap, so that this cannot write
	// an older mapping over a rebuild that landed while it was working, and so
	// that a burst of refreshes of one user costs one write rather than one
	// each: whichever gets here second finds nothing left to change.
	d.applyMu.Lock()
	defer d.applyMu.Unlock()

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

// searchUser searches every backend for one user and merges what they hold,
// exactly as a rebuild merges the whole of every backend: a user held in more
// than one directory ends up with the union of their groups.
//
// A backend that cannot be searched fails the search rather than being left
// out of it, as it fails a rebuild. Answering with the groups the reachable
// directories hold would hand the user an authorization identity missing
// whatever the other one gives them, which is worse than leaving the mapping
// as it was.
func (d *Directory) searchUser(key string) ([]string, bool, error) {
	type result struct {
		groups []string
		found  bool
		err    error
	}

	results := make([]result, len(d.backends))
	var wg sync.WaitGroup
	for i, b := range d.backends {
		wg.Add(1)
		go func() {
			defer wg.Done()

			groups, found, err := b.searchUser(key)
			if err != nil {
				results[i].err = fmt.Errorf("backend %q: %s", b.config.Name, err)
				return
			}

			results[i] = result{groups: groups, found: found}
		}()
	}
	wg.Wait()

	merged := make(map[string][]string)
	var found bool
	for _, result := range results {
		if result.err != nil {
			return nil, false, result.err
		}

		if !result.found {
			continue
		}

		found = true
		merge(merged, map[string][]string{key: result.groups})
	}

	if !found {
		return nil, false, nil
	}

	finalise(merged)

	return merged[key], true, nil
}

// searchUser searches this backend for one user, returning the groups they
// hold in it. The second return value reports whether the backend holds them
// at all.
//
// The groups they are a member of are resolved against the group names of the
// last rebuild rather than by sweeping the group search bases again, which is
// most of what makes refreshing one user cheaper than rebuilding everybody. A
// group the last rebuild did not find is looked up on its own - see
// discoverGroup, and the reason a refresh would be useless without it.
func (b *backend) searchUser(username string) ([]string, bool, error) {
	groupNames := b.lastGroupNames.Load()
	if groupNames == nil {
		return nil, false, errors.New("has not been searched yet, so there are no groups to resolve against")
	}

	w := newWatchdog(b.config.Timeout.Duration())
	defer w.stop()

	c, err := b.connect(w)
	if err != nil {
		return nil, false, w.wrap(err)
	}
	defer c.Close()

	// The username is a value from an authenticated request, so it reaches the
	// filter escaped: a name carrying parentheses or an asterisk must not be
	// able to widen the search it appears in.
	filter := fmt.Sprintf("(&%s(%s=%s))", b.config.UserFilter, b.config.UsernameAttribute,
		goldap.EscapeFilter(username))

	var groups []string
	var claimedBy string

	for _, base := range b.config.UserSearchBases {
		req := goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, b.timeLimit(), false, filter, []string{b.config.UsernameAttribute, memberOfAttribute}, nil)

		res, err := c.Search(req)
		if err != nil {
			return nil, false, w.wrap(fmt.Errorf("failed to search for user %q in %q: %s", username, base, err))
		}

		for _, entry := range res.Entries {
			// The mapping is keyed on the attribute value, so an entry is only
			// this user if that is what it holds. A directory is free to match
			// a filter by rules of its own - case, trailing spaces - and an
			// entry it returned for a name that is not the one asked for would
			// otherwise be cached under the name that was.
			if !strings.EqualFold(attributeValue(entry, b.config.UsernameAttribute), username) {
				continue
			}

			if claimedBy != "" {
				claimedDN, err := normaliseDN(claimedBy)
				if err != nil {
					return nil, false, fmt.Errorf("user %q has an invalid DN: %s", claimedBy, err)
				}

				entryDN, err := normaliseDN(entry.DN)
				if err != nil {
					return nil, false, fmt.Errorf("user %q has an invalid DN: %s", entry.DN, err)
				}

				// Overlapping search bases return one entry more than once,
				// which carries the same groups either way. Two entries are
				// the ambiguity a rebuild refuses, and it is refused here too:
				// which of them a request should run as does not become any
				// clearer for having been asked about one user.
				if claimedDN != entryDN {
					return nil, false, w.wrap(&duplicateUserError{
						username: username, first: claimedBy, second: entry.DN,
					})
				}

				continue
			}

			claimedBy = entry.DN

			dns, err := b.memberOfDNs(c, entry)
			if err != nil {
				return nil, false, w.wrap(err)
			}

			groups, err = groupsFromDNs(entry.DN, dns, *groupNames, b.discoverGroup(c, *groupNames))
			if err != nil {
				return nil, false, w.wrap(err)
			}
		}
	}

	if claimedBy == "" {
		return nil, false, nil
	}

	return groups, true, nil
}

// discoverGroup answers for a group the last rebuild did not find.
//
// Adding a user to a group that was created since then is the change somebody
// is most likely to be asking to have picked up, so resolving their membership
// only against what that rebuild found would leave the refresh doing nothing in
// the case it exists for. The group is looked up on its own instead, which is
// one search for a DN rather than another sweep of the search bases.
//
// It is held to the same rules the sweep holds a group to: it must live under a
// configured group search base, match the group filter, carry a name, not use
// the reserved system: prefix, and not collide with the name of a group already
// in the mapping. A DN that fails any of those is left out, exactly as it would
// have been by a rebuild - except a collision, which fails the refresh as it
// fails a rebuild, since there is no answer to give.
func (b *backend) discoverGroup(c conn, groupNames map[string]string) func(string, string) (string, error) {
	var discovered int

	return func(groupDN, key string) (string, error) {
		// A user is routinely a member of groups outside the search bases, and
		// those are meant to be dropped. Answering that from the DN costs
		// nothing, and leaves the searches below for the DNs that could
		// genuinely be a group this proxy has not heard of yet.
		if !b.underGroupSearchBase(key) {
			return "", nil
		}

		// A refresh that has to discover this many groups is looking at a
		// mapping too far out of date for one user to be the right unit of
		// work, and would be searching the directory once per group to catch
		// up. Say so rather than quietly returning some of them.
		if discovered == maxGroupDiscoveries {
			return "", fmt.Errorf("more than %d groups of %q are missing from the last rebuild, "+
				"so refresh the whole mapping rather than one user", maxGroupDiscoveries, groupDN)
		}
		discovered++

		req := goldap.NewSearchRequest(groupDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
			0, b.timeLimit(), false, b.config.GroupFilter, []string{b.config.GroupNameAttribute}, nil)

		res, err := c.Search(req)
		if err != nil {
			// A memberOf naming a group that has since been deleted is an
			// ordinary state, not a directory that cannot be searched.
			if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
				klog.V(4).Infof("group %q of backend %q no longer exists", groupDN, b.config.Name)
				return "", nil
			}

			return "", fmt.Errorf("failed to look up group %q: %s", groupDN, err)
		}

		if len(res.Entries) == 0 {
			// Under a search base, but not a group as this backend defines
			// one. A rebuild would not have mapped it either.
			return "", nil
		}

		name := attributeValue(res.Entries[0], b.config.GroupNameAttribute)
		if name == "" {
			klog.V(4).Infof("skipping group %q with no %q attribute", groupDN, b.config.GroupNameAttribute)
			return "", nil
		}

		emitted := b.config.GroupPrefix + name
		if strings.HasPrefix(emitted, kubernetesSystemGroupPrefix) {
			klog.Warningf("skipping group %q: emitted name %q uses the reserved %s prefix",
				groupDN, emitted, kubernetesSystemGroupPrefix)
			return "", nil
		}

		// Once the DN is discarded there is no way for RBAC to tell two
		// directory groups of one name apart, so a new group taking the name of
		// one already in the mapping is the ambiguity a rebuild refuses.
		for existing, existingName := range groupNames {
			if existingName == emitted && existing != key {
				return "", &duplicateGroupError{name: emitted, first: existing, second: groupDN}
			}
		}

		klog.V(2).Infof("group %q of backend %q was created since the last rebuild, mapping it to %q",
			groupDN, b.config.Name, emitted)

		return emitted, nil
	}
}

// underGroupSearchBase reports whether a normalised DN lies under one of the
// configured group search bases, which is the same restriction the sweep gets
// from searching those bases and nothing else.
func (b *backend) underGroupSearchBase(key string) bool {
	for _, base := range b.groupBaseKeys {
		if key == base || strings.HasSuffix(key, ","+base) {
			return true
		}
	}

	return false
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
