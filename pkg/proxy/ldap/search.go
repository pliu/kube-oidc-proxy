// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"k8s.io/klog/v2"
)

const (
	// maxGroupDiscoveries bounds direct group resolutions for one user.
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
// unknown resolves a DN that has not yet been seen in this lookup.
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

// searchUserContext queries every backend and unions only complete successful results.
func (d *resolver) searchUserContext(ctx context.Context, key string) ([]string, bool, error) {
	type foundUser struct {
		groups []string
		found  bool
	}

	results, err := eachBackend(d.backends, func(b *backend) (foundUser, error) {
		start := time.Now()
		groups, found, err := b.searchUserContext(ctx, key)
		if err == nil {
			backendRefreshDuration.WithLabelValues(b.config.Name).Observe(time.Since(start).Seconds())
		}
		return foundUser{groups: groups, found: found}, err
	})
	if err != nil {
		return nil, false, err
	}

	groups := make([]string, 0)
	seen := make(map[string]struct{})
	found := false
	for _, result := range results {
		found = found || result.found
		for _, group := range result.groups {
			if _, duplicate := seen[group]; duplicate {
				continue
			}
			seen[group] = struct{}{}
			groups = append(groups, group)
		}
	}
	if !found {
		return nil, false, nil
	}
	sort.Strings(groups)
	return groups, true, nil
}

// searchUserContext searches this backend for one user, returning the groups they
// hold in it. The second return value reports whether the backend holds them
// at all.
//
// Membership DNs are resolved directly within configured group search bases.
func (b *backend) searchUserContext(ctx context.Context, username string) ([]string, bool, error) {
	groupNames := make(map[string]string)

	var groups []string
	var claimedBy string

	err := b.withConnContext(ctx, func(c conn) error {
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
				// Cached identities use the attribute value, so an entry is only
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
					// ambiguous identities and must be refused:
					// which of them a request should run as does not become any
					// clearer for having been asked about one user.
					if err := rejectDuplicateUser(username, claimedBy, entry.DN); err != nil {
						return err
					}

					continue
				}

				claimedBy = entry.DN

				var err error
				groups, err = b.groupsOf(c, entry, groupNames, b.discoverGroup(c, groupNames))
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

// discoverGroup resolves membership DNs within configured bases and filters.
// The per-lookup map also detects ambiguous group names.
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

		// Fail the complete lookup when its work limit is exceeded.
		if discovered == maxGroupDiscoveries {
			return "", fmt.Errorf("single-user lookup exceeds the limit of %d group resolutions at %q", maxGroupDiscoveries, groupDN)
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
			// one.
			return "", nil
		}

		name := emittedGroupName(groupDN, attributeValue(res.Entries[0], b.config.GroupNameAttribute),
			b.config.GroupNameAttribute)
		if name == "" {
			return "", nil
		}

		// Once the DN is discarded there is no way for RBAC to tell two
		// directory groups of one name apart, so a new group taking the name of
		// one already resolved is an ambiguous authorization identity.
		for existing, existingName := range groupNames {
			if existingName == name && existing != key {
				return "", &duplicateGroupError{name: name, first: existing, second: groupDN}
			}
		}

		// Check ambiguity by exact emitted name, without enumerating groups.
		for _, base := range b.config.GroupSearchBases {
			filter := fmt.Sprintf("(&%s(%s=%s))", b.config.GroupFilter, b.config.GroupNameAttribute, goldap.EscapeFilter(name))
			matches, err := c.Search(goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
				2, b.timeLimit(), false, filter, []string{b.config.GroupNameAttribute}, nil))
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
		groupNames[key] = name

		return name, nil
	}
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
	if skipEmptyGroup(dn, name, attr) || skipReservedGroup(dn, name) {
		return ""
	}

	return name
}

func skipEmptyGroup(dn, name, attr string) bool {
	if name != "" {
		return false
	}

	klog.V(4).Infof("skipping group %q with no %q attribute", dn, attr)
	return true
}

func skipReservedGroup(dn, name string) bool {
	if !strings.HasPrefix(name, kubernetesSystemGroupPrefix) {
		return false
	}

	klog.Warningf("skipping group %q: name %q uses the reserved %s prefix",
		dn, name, kubernetesSystemGroupPrefix)
	return true
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
