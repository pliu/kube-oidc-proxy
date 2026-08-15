// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"k8s.io/klog/v2"
)

// buildResult is one rebuild of the mapping, in configuration order per
// backend, kept together so that everything a refresh has to record about it
// moves as one thing.
type buildResult struct {
	mapping map[string][]string
	groups  int
	stats   []BackendStats

	// groupNames is the group DN -> emitted name mapping each backend resolved
	// its users against, which a refresh that is accepted leaves on the
	// backends for single user searches to use.
	groupNames []map[string]string
}

// backendBuild is what one backend contributed to a rebuild.
type backendBuild struct {
	mapping    map[string][]string
	groups     int
	stats      BackendStats
	groupNames map[string]string
}

// build searches every backend and returns the merged username -> groups
// mapping, along with how many groups were considered: the sum over the
// backends of the groups found under their search bases. That is not the number
// of distinct group names in the mapping - it counts a group no user in the
// search bases belongs to, and counts a group twice if two backends both found
// it - so nothing that decides what is served is derived from it.
//
// A backend that cannot be searched, or that has stopped returning anything at
// all, fails the whole refresh. Merging what the healthy backends returned
// would quietly drop the groups a user holds in the other one, which is worse
// than serving a mapping that is a refresh interval out of date.
func (d *Directory) build() (*buildResult, error) {
	results, err := eachBackend(d.backends, func(b *backend) (backendBuild, error) {
		start := time.Now()
		built, builtGroupNames, err := b.build()
		if err != nil {
			return backendBuild{}, err
		}

		builtGroups := len(builtGroupNames)
		if err := b.checkCounts(len(built), builtGroups); err != nil {
			return backendBuild{}, err
		}

		took := time.Since(start)
		backendRefreshDuration.WithLabelValues(b.config.Name).Observe(took.Seconds())

		klog.V(4).Infof("built LDAP mapping from backend %q: %d users, %d groups (%s)",
			b.config.Name, len(built), builtGroups, took)

		return backendBuild{
			mapping:    built,
			groups:     builtGroups,
			groupNames: builtGroupNames,
			stats: BackendStats{
				Name:     b.config.Name,
				Users:    len(built),
				Groups:   builtGroups,
				Duration: took.String(),
			},
		}, nil
	})
	if err != nil {
		return nil, err
	}

	built := &buildResult{
		mapping:    make(map[string][]string),
		stats:      make([]BackendStats, 0, len(results)),
		groupNames: make([]map[string]string, 0, len(results)),
	}

	for _, result := range results {
		merge(built.mapping, result.mapping)
		built.groups += result.groups
		built.stats = append(built.stats, result.stats)
		built.groupNames = append(built.groupNames, result.groupNames)
	}

	finalise(built.mapping)

	return built, nil
}

// merge folds the mapping of one backend into the combined mapping. A user
// held in more than one directory ends up with the union of their groups.
func merge(into, from map[string][]string) {
	for username, groups := range from {
		existing, ok := into[username]
		if !ok {
			into[username] = groups
			continue
		}

		// Two directories can name the same group, and a user must not be
		// impersonated as a member of it twice.
		seen := make(map[string]struct{}, len(existing))
		for _, group := range existing {
			seen[group] = struct{}{}
		}

		for _, group := range groups {
			if _, duplicate := seen[group]; duplicate {
				continue
			}

			seen[group] = struct{}{}
			existing = append(existing, group)
		}

		into[username] = existing
	}
}

// finalise sorts the groups of every user, so that the mapping does not depend
// on the order the backends happened to return, and clips each slice to its
// length. The mapping is shared by every request, so a caller appending to the
// groups of a user then gets a copy rather than writing into spare capacity
// that other requests can see.
func finalise(mapping map[string][]string) {
	for username, groups := range mapping {
		sort.Strings(groups)
		mapping[username] = groups[:len(groups):len(groups)]
	}
}

// build searches this backend and returns a username -> groups mapping, along
// with the normalised group DN -> emitted name mapping it was resolved against.
// The size of that mapping is how many distinct groups were found under the
// group search bases: a group nobody in the user search bases belongs to is
// counted, since what it measures is the search having returned something
// rather than the mapping.
func (b *backend) build() (map[string][]string, map[string]string, error) {
	var mapping map[string][]string
	var groupNames map[string]string

	err := b.withConn(func(c conn) error {
		var err error
		groupNames, err = b.searchGroups(c)
		if err != nil {
			recordDuplicate(b.config.Name, err)
			return err
		}
		backendDuplicateValues.WithLabelValues(b.config.Name, duplicateKindGroup).Set(0)

		mapping, err = b.searchUsers(c, groupNames)
		if err != nil {
			recordDuplicate(b.config.Name, err)
			return err
		}
		backendDuplicateValues.WithLabelValues(b.config.Name, duplicateKindUser).Set(0)

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return mapping, groupNames, nil
}

// recordDuplicate publishes a metric when a search failed because two entries
// of one backend collapsed into one authorization identity.
func recordDuplicate(name string, err error) {
	var duplicateGroup *duplicateGroupError
	if errors.As(err, &duplicateGroup) {
		backendDuplicateValues.WithLabelValues(name, duplicateKindGroup).Set(1)
		return
	}

	var duplicateUser *duplicateUserError
	if errors.As(err, &duplicateUser) {
		backendDuplicateValues.WithLabelValues(name, duplicateKindUser).Set(1)
	}
}

// checkCounts rejects a backend that has stopped returning anything at all.
//
// A search that comes back empty is not an error at the protocol level, so
// without this a backend that answers but finds nothing is merged in as a
// backend that contributes nothing: a bind account that loses its read on the
// user OU, or a search base renamed out from under the configuration, silently
// strips every user of that directory of their groups. Treating the collapse
// as a failure keeps the last good mapping serving instead, which is the same
// choice made for a backend that cannot be reached at all.
//
// Only a fall to zero is caught, not a directory that merely shrinks - any
// threshold short of that would be a guess at how much churn is normal. A
// directory that has legitimately been emptied is accepted once the proxy is
// restarted and its persisted mapping removed.
func (b *backend) checkCounts(users, groups int) error {
	switch {
	case b.lastUsers > 0 && users == 0:
		return fmt.Errorf("returned no users, having returned %d at the last refresh", b.lastUsers)

	case b.lastGroups > 0 && groups == 0:
		return fmt.Errorf("returned no groups, having returned %d at the last refresh", b.lastGroups)
	}

	return nil
}
