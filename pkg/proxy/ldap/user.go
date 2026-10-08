// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

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

// equalGroups compares sorted membership lists.
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
