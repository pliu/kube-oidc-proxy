// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import "sort"

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
