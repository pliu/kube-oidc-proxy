// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"errors"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"k8s.io/klog/v2"
)

// maxGroupDiscoveries bounds the groups one refresh of a user will look up
// individually, so that a mapping far enough out of date cannot turn refreshing
// one user into a search per group they hold.
const maxGroupDiscoveries = 100

// searchGroups returns a mapping of normalised group DN -> group name for
// every group under the configured group search bases.
func (b *backend) searchGroups(c conn) (map[string]string, error) {
	groupNames := make(map[string]string)
	type groupClaim struct {
		key string
		dn  string
	}
	claimedByName := make(map[string]groupClaim)

	for _, base := range b.config.GroupSearchBases {
		req := goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, b.timeLimit(), false, b.config.GroupFilter, []string{b.config.GroupNameAttribute}, nil)

		res, err := c.SearchWithPaging(req, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to search groups in %q: %s", base, err)
		}

		for _, entry := range res.Entries {
			name := emittedGroupName(entry.DN, attributeValue(entry, b.config.GroupNameAttribute),
				b.config.GroupNameAttribute)
			if name == "" {
				continue
			}

			key, err := normaliseDN(entry.DN)
			if err != nil {
				return nil, fmt.Errorf("group %q has an invalid DN: %s", entry.DN, err)
			}

			if claimed, ok := claimedByName[name]; ok && claimed.key != key {
				return nil, &duplicateGroupError{name: name, first: claimed.dn, second: entry.DN}
			}

			claimedByName[name] = groupClaim{key: key, dn: entry.DN}
			groupNames[key] = name
		}
	}

	return groupNames, nil
}

// searchUsers returns a mapping of lower cased username -> group names, using
// the memberOf attribute of each user filtered down to the known groups.
//
// Two entries of one directory that claim the same username fail the rebuild.
// Which of them a request should be authorized as is genuinely ambiguous, and
// resolving it by taking whichever the directory happened to return last would
// hand a user groups that depend on search order.
func (b *backend) searchUsers(c conn, groupNames map[string]string) (map[string][]string, error) {
	mapping := make(map[string][]string)

	// claimedBy holds the DN that a username was found on, so that two entries
	// claiming one identity can be told apart from one entry returned twice by
	// search bases that overlap.
	claimedBy := make(map[string]string)

	for _, base := range b.config.UserSearchBases {
		req := goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, b.timeLimit(), false, b.config.UserFilter,
			[]string{b.config.UsernameAttribute, memberOfAttribute}, nil)

		res, err := c.SearchWithPaging(req, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to search users in %q: %s", base, err)
		}

		for _, entry := range res.Entries {
			username := attributeValue(entry, b.config.UsernameAttribute)
			if username == "" {
				klog.V(4).Infof("skipping user %q with no %q attribute", entry.DN, b.config.UsernameAttribute)
				continue
			}

			key := strings.ToLower(username)

			if claimed, ok := claimedBy[key]; ok {
				// One entry returned again because the search bases overlap
				// carries the same groups either way, so it is not ambiguous.
				if err := rejectDuplicateUser(username, claimed, entry.DN); err != nil {
					return nil, err
				}

				continue
			}

			claimedBy[key] = entry.DN

			groups, err := b.groupsOf(c, entry, groupNames, nil)
			if err != nil {
				return nil, err
			}

			mapping[key] = groups
		}
	}

	return mapping, nil
}

// groupsOf turns the memberOf of one entry into the group names it is to be
// given.
func (b *backend) groupsOf(c conn, entry *goldap.Entry, groupNames map[string]string,
	unknown func(groupDN, key string) (string, error)) ([]string, error) {
	dns, err := b.memberOfDNs(c, entry)
	if err != nil {
		return nil, err
	}

	return groupsFromDNs(entry.DN, dns, groupNames, unknown)
}

// groupsFromDNs turns the memberOf of one entry into the group names it is to
// be given, keeping only the groups that were found under the configured group
// search bases. A group named twice - by two DNs that normalise the same way -
// is given once, since a user must not be impersonated as a member of it
// twice.
//
// unknown is asked about a DN that groupNames does not hold, and returns the
// name to give it or "" to leave it out. A rebuild passes nil: it has just read
// every group there is, so a DN it does not recognise is one that lives outside
// the search bases and is meant to be dropped.
func groupsFromDNs(dn string, memberOf []string, groupNames map[string]string,
	unknown func(groupDN, key string) (string, error)) ([]string, error) {
	groups := make([]string, 0)
	seen := make(map[string]struct{})

	for _, groupDN := range memberOf {
		key, err := normaliseDN(groupDN)
		if err != nil {
			return nil, fmt.Errorf("user %q has an invalid %s DN %q: %s",
				dn, memberOfAttribute, groupDN, err)
		}

		name, ok := groupNames[key]
		if !ok {
			if unknown == nil {
				continue
			}

			if name, err = unknown(groupDN, key); err != nil {
				return nil, err
			}

			if name == "" {
				continue
			}
		}

		if _, duplicate := seen[name]; duplicate {
			continue
		}

		seen[name] = struct{}{}
		groups = append(groups, name)
	}

	return groups, nil
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
	type foundUser struct {
		groups []string
		found  bool
	}

	results, err := eachBackend(d.backends, func(b *backend) (foundUser, error) {
		groups, found, err := b.searchUser(key)
		return foundUser{groups: groups, found: found}, err
	})
	if err != nil {
		return nil, false, err
	}

	merged := make(map[string][]string)
	var found bool
	for _, result := range results {
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

	var groups []string
	var claimedBy string

	err := b.withConn(func(c conn) error {
		// The username is a value from an authenticated request, so it reaches the
		// filter escaped: a name carrying parentheses or an asterisk must not be
		// able to widen the search it appears in.
		filter := fmt.Sprintf("(&%s(%s=%s))", b.config.UserFilter, b.config.UsernameAttribute,
			goldap.EscapeFilter(username))

		for _, base := range b.config.UserSearchBases {
			req := goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
				0, b.timeLimit(), false, filter, []string{b.config.UsernameAttribute, memberOfAttribute}, nil)

			res, err := c.Search(req)
			if err != nil {
				return fmt.Errorf("failed to search for user %q in %q: %s", username, base, err)
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
					// Overlapping search bases return one entry more than once,
					// which carries the same groups either way. Two entries are
					// the ambiguity a rebuild refuses, and it is refused here too:
					// which of them a request should run as does not become any
					// clearer for having been asked about one user.
					if err := rejectDuplicateUser(username, claimedBy, entry.DN); err != nil {
						return err
					}

					continue
				}

				claimedBy = entry.DN

				var err error
				groups, err = b.groupsOf(c, entry, *groupNames, b.discoverGroup(c, *groupNames))
				if err != nil {
					return err
				}
			}
		}

		return nil
	})
	if err != nil {
		return nil, false, err
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

		name := emittedGroupName(groupDN, attributeValue(res.Entries[0], b.config.GroupNameAttribute),
			b.config.GroupNameAttribute)
		if name == "" {
			return "", nil
		}

		// Once the DN is discarded there is no way for RBAC to tell two
		// directory groups of one name apart, so a new group taking the name of
		// one already in the mapping is the ambiguity a rebuild refuses.
		for existing, existingName := range groupNames {
			if existingName == name && existing != key {
				return "", &duplicateGroupError{name: name, first: existing, second: groupDN}
			}
		}

		klog.V(2).Infof("group %q of backend %q was created since the last rebuild, mapping it to %q",
			groupDN, b.config.Name, name)

		return name, nil
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

// emittedGroupName returns the group name to impersonate, or "" if the group
// should be left out of the mapping: it has no name attribute, or the name
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
		return err
	}

	if !same {
		return &duplicateUserError{username: username, first: first, second: second}
	}

	return nil
}
