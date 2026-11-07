// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"fmt"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"k8s.io/klog/v2"
)

const (
	// maxGroupDiscoveries bounds the distinct groups under the search bases
	// that one user can have resolved.
	maxGroupDiscoveries = 1000

	// kubernetesSystemGroupPrefix is reserved by Kubernetes for built-in
	// groups such as system:masters. Impersonating a caller as a member of
	// those groups would grant privileges the directory must not be able to
	// confer.
	kubernetesSystemGroupPrefix = "system:"
)

// duplicateUserError reports two entries of one backend claiming one username.
type duplicateUserError struct {
	username string
	first    string
	second   string
}

// duplicateGroupError reports two entries of one backend collapsing into the
// same Kubernetes group name. Once the DN is discarded there is no way for
// RBAC to tell those directory groups apart.
type duplicateGroupError struct {
	name   string
	first  string
	second string
}

func (e *duplicateGroupError) Error() string {
	return fmt.Sprintf("group name %q is held by both %q and %q, so the authorization identity is ambiguous",
		e.name, e.first, e.second)
}

func (e *duplicateUserError) Error() string {
	return fmt.Sprintf("%q is held by both %q and %q, so the groups to give them are ambiguous",
		e.username, e.first, e.second)
}

// groupsOf turns the memberOf of one entry into the group names it is to be
// given, keeping only the groups that were found under the configured group
// search bases. A group named twice is given twice here; the record built from
// the groups is the one place they are ordered and deduplicated. resolve is
// shared by every user of a batch, so a group held by many of them is read
// from the directory once.
func (b *backend) groupsOf(c conn, entry *goldap.Entry, resolve *groupResolver) ([]string, error) {
	dns, err := b.memberOfDNs(c, entry)
	if err != nil {
		return nil, err
	}

	var groups []string
	// held counts the distinct groups under the search bases that this user
	// asks to be resolved, whether or not another user of the batch already
	// resolved them, so that the limit does not depend on who was batched
	// together.
	held := make(map[string]struct{})

	for _, groupDN := range dns {
		key, err := normaliseDN(groupDN)
		if err != nil {
			return nil, fmt.Errorf("user %q has an invalid %s DN %q: %s",
				entry.DN, memberOfAttribute, groupDN, err)
		}

		// A user is routinely a member of groups outside the search bases, and
		// those are meant to be dropped. Answering that from the DN costs
		// nothing, and leaves the searches for the DNs that could genuinely be
		// a group this proxy has not heard of yet.
		if !b.underGroupSearchBase(key) {
			continue
		}

		if _, ok := held[key]; !ok {
			// Fail the complete lookup when its work limit is exceeded.
			if len(held) == maxGroupDiscoveries {
				return nil, fmt.Errorf("single-user lookup exceeds the limit of %d group resolutions at %q", maxGroupDiscoveries, groupDN)
			}
			held[key] = struct{}{}
		}

		name, err := resolve.name(groupDN, key)
		if err != nil {
			return nil, err
		}

		if name != "" {
			groups = append(groups, name)
		}
	}

	return groups, nil
}

// userResult is what was found for one user of a batch: their groups, or why
// they could not be given any.
type userResult struct {
	groups []string
	err    error
}

// searchUser queries every backend for one user and unions only complete
// successful results, for a request.
func (d *resolver) searchUser(ctx context.Context, key string) ([]string, error) {
	results, err := d.searchUsers(ctx, []string{key}, false)
	if err != nil {
		return nil, err
	}

	return results[0].groups, results[0].err
}

// searchUsers queries every backend for a batch of users and, for each user,
// unions only complete successful results, in the order of keys. A backend
// that cannot be searched fails the whole batch and is returned as the error;
// a user that any backend rejects fails alone, in their result.
func (d *resolver) searchUsers(ctx context.Context, keys []string, refresh bool) ([]userResult, error) {
	trigger := triggerRealtime
	if refresh {
		trigger = triggerAsync
	}
	perBackend, err := eachBackend(d.backends, func(b *backend) ([]userResult, error) {
		start := time.Now()
		results, err := b.searchUsers(ctx, keys)
		if err != nil {
			return nil, err
		}
		backendRefreshDuration.WithLabelValues(b.config.Name, trigger).Observe(time.Since(start).Seconds())
		for i := range results {
			if results[i].err != nil {
				results[i].err = fmt.Errorf("backend %q: %w", b.config.Name, results[i].err)
			}
		}
		return results, nil
	})
	if err != nil {
		return nil, err
	}

	// Groups are ordered and deduplicated by the record built from them,
	// which is the one place memberships are normalized.
	merged := make([]userResult, len(keys))
	for i := range keys {
		for _, results := range perBackend {
			// The first rejection in configuration order, so that errors stay
			// deterministic.
			if results[i].err != nil {
				merged[i] = userResult{err: results[i].err}
				break
			}
			merged[i].groups = append(merged[i].groups, results[i].groups...)
		}
	}

	return merged, nil
}

// searchUsers searches this backend for a batch of users on one connection,
// returning the groups each holds in it in the order of usernames. Missing
// users hold no groups. The users are found with one search per user search
// base, and each group is resolved once for the whole batch.
//
// An error returned means the backend could not be searched, and fails every
// user. A user whose entries or groups are rejected fails alone.
//
// Membership DNs are resolved directly within configured group search bases.
func (b *backend) searchUsers(ctx context.Context, usernames []string) ([]userResult, error) {
	var results []userResult

	err := b.withConn(ctx, func(c conn) error {
		// withConn runs this again on a fresh connection when a pooled one
		// fails, so nothing found on the first attempt may carry over.
		results = make([]userResult, len(usernames))
		entries := make([]*goldap.Entry, len(usernames))
		filter := b.userFilter(usernames)

		for _, base := range b.config.UserSearchBases {
			res, err := c.Search(b.searchRequest(base, goldap.ScopeWholeSubtree, 0, filter,
				b.config.UsernameAttribute, memberOfAttribute))
			if err != nil {
				return fmt.Errorf("failed to search for %s in %q: %s", describeUsers(usernames), base, err)
			}

			for _, entry := range res.Entries {
				value := attributeValue(entry, b.config.UsernameAttribute)

				for i, username := range usernames {
					// Cached identities use the attribute value, so an entry is
					// only this user if that is what it holds. A directory is free
					// to match a filter by rules of its own - case, trailing
					// spaces - and an entry it returned for a name that is not the
					// one asked for would otherwise be cached under the name that
					// was.
					if results[i].err != nil || !strings.EqualFold(value, username) {
						continue
					}

					if entries[i] == nil {
						entries[i] = entry
						continue
					}

					// Overlapping search bases return one entry more than once,
					// which carries the same groups either way. Two entries are
					// ambiguous identities and must be refused: which of them a
					// request should run as does not become any clearer for
					// having been asked about one user.
					results[i].err = rejectDuplicateUser(username, entries[i].DN, entry.DN)
				}
			}
		}

		// A search that leaves the connection in doubt fails the batch, so that
		// withConn can retry it on a fresh connection, rather than failing
		// every user after it on a connection that is likely gone.
		watched := &watchedConn{conn: c}
		resolve := b.newGroupResolver(watched)

		for i, entry := range entries {
			if entry == nil || results[i].err != nil {
				continue
			}

			groups, err := b.groupsOf(watched, entry, resolve)
			if watched.broken {
				return err
			}

			results[i] = userResult{groups: groups, err: err}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}

// userFilter matches any of usernames among the configured users. The
// usernames are values from authenticated requests, so they reach the filter
// escaped: a name carrying parentheses or an asterisk must not be able to
// widen the search it appears in.
func (b *backend) userFilter(usernames []string) string {
	var match strings.Builder
	for _, username := range usernames {
		fmt.Fprintf(&match, "(%s=%s)", b.config.UsernameAttribute, goldap.EscapeFilter(username))
	}

	if len(usernames) == 1 {
		return fmt.Sprintf("(&%s%s)", b.config.UserFilter, match.String())
	}

	return fmt.Sprintf("(&%s(|%s))", b.config.UserFilter, match.String())
}

// describeUsers names the users of a search in an error.
func describeUsers(usernames []string) string {
	if len(usernames) == 1 {
		return fmt.Sprintf("user %q", usernames[0])
	}

	return fmt.Sprintf("%d users", len(usernames))
}

// groupResolver resolves membership DNs within configured bases and filters
// for one batch on one connection. It remembers each answer, a rejection
// included, so that every user holding a group gets the same one, and detects
// group names held by more than one DN.
type groupResolver struct {
	b      *backend
	c      conn
	groups map[string]resolvedGroup // by normalised DN
	byName map[string]string        // normalised DN by emitted name
}

type resolvedGroup struct {
	name string
	err  error
}

func (b *backend) newGroupResolver(c conn) *groupResolver {
	return &groupResolver{b: b, c: c, groups: make(map[string]resolvedGroup), byName: make(map[string]string)}
}

// name returns the emitted name of the group at groupDN, whose normalised form
// is key and lies under a group search base, or "" if it is not to be given.
func (r *groupResolver) name(groupDN, key string) (string, error) {
	if group, ok := r.groups[key]; ok {
		return group.name, group.err
	}

	name, err := r.resolve(groupDN, key)
	if err == nil && name != "" {
		// Once the DN is discarded there is no way for RBAC to tell two
		// directory groups of one name apart, so a new group taking the name
		// of one already resolved is an ambiguous authorization identity.
		if existing, ok := r.byName[name]; ok && existing != key {
			name, err = "", &duplicateGroupError{name: name, first: existing, second: groupDN}
		} else {
			r.byName[name] = key
		}
	}

	r.groups[key] = resolvedGroup{name: name, err: err}

	return name, err
}

// resolve reads one group from the directory and checks that its emitted name
// is held by no other group under the search bases.
func (r *groupResolver) resolve(groupDN, key string) (string, error) {
	b, c := r.b, r.c

	res, err := c.Search(b.searchRequest(groupDN, goldap.ScopeBaseObject, 0, b.config.GroupFilter,
		b.config.GroupNameAttribute))
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
		// Under a search base, but not a group as this backend defines one.
		return "", nil
	}

	name := emittedGroupName(groupDN, attributeValue(res.Entries[0], b.config.GroupNameAttribute),
		b.config.GroupNameAttribute)
	if name == "" {
		return "", nil
	}

	// Check ambiguity by exact emitted name, without enumerating groups.
	for _, base := range b.config.GroupSearchBases {
		filter := fmt.Sprintf("(&%s(%s=%s))", b.config.GroupFilter, b.config.GroupNameAttribute, goldap.EscapeFilter(name))
		matches, err := c.Search(b.searchRequest(base, goldap.ScopeWholeSubtree, 2, filter,
			b.config.GroupNameAttribute))
		if err != nil {
			return "", fmt.Errorf("check group identity %q: %w", name, err)
		}
		for _, candidate := range matches.Entries {
			if attributeValue(candidate, b.config.GroupNameAttribute) != name {
				continue
			}
			candidateKey, err := normaliseDN(candidate.DN)
			if err != nil {
				return "", err
			}
			if candidateKey != key {
				return "", &duplicateGroupError{name: name, first: candidate.DN, second: groupDN}
			}
		}
	}

	return name, nil
}

// searchRequest builds a search of base for attributes, never dereferencing
// aliases and held to the backend's time limit. sizeLimit 0 is unlimited.
func (b *backend) searchRequest(base string, scope, sizeLimit int, filter string, attributes ...string) *goldap.SearchRequest {
	return goldap.NewSearchRequest(base, scope, goldap.NeverDerefAliases,
		sizeLimit, b.timeLimit(), false, filter, attributes, nil)
}

// underGroupSearchBase reports whether a normalised DN lies under one of the
// configured group search bases.
func (b *backend) underGroupSearchBase(key string) bool {
	for _, base := range b.groupBaseKeys {
		if key == base || strings.HasSuffix(key, ","+base) {
			return true
		}
	}

	return false
}

// emittedGroupName returns the group name to impersonate, or "" if the group
// should be left out of the memberships: it has no name attribute, or the name
// uses the reserved system: prefix.
func emittedGroupName(dn, name, attr string) string {
	if name == "" {
		klog.V(4).Infof("skipping group %q with no %q attribute", dn, attr)
		return ""
	}
	if strings.HasPrefix(name, kubernetesSystemGroupPrefix) {
		klog.Warningf("skipping group %q: name %q uses the reserved %s prefix",
			dn, name, kubernetesSystemGroupPrefix)
		return ""
	}
	return name
}

// rejectDuplicateUser fails when two DNs claim the same username. Overlapping
// search bases that return one entry twice are accepted.
func rejectDuplicateUser(username, first, second string) error {
	same, err := sameDN(first, second)
	if err != nil {
		return fmt.Errorf("user %s", err)
	}

	if !same {
		return &duplicateUserError{username: username, first: first, second: second}
	}

	return nil
}
