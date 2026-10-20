// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// normaliseDN makes DNs comparable across the group and memberOf attributes.
// LDAP can spell the same DN with different case, whitespace, escapes and
// ordering inside a multi-valued RDN, so it must be parsed as RFC 4514 rather
// than split on commas (which may themselves be escaped inside a value).
func normaliseDN(dn string) (string, error) {
	parsed, err := goldap.ParseDN(dn)
	if err != nil {
		return "", err
	}

	// DN matching in the directories this augmenter supports is intentionally
	// case insensitive. Lowercase values before String sorts the attributes of
	// a multi-valued RDN, so equivalent RDNs produce the same key even when the
	// input used different case and attribute order.
	for _, rdn := range parsed.RDNs {
		for _, attribute := range rdn.Attributes {
			attribute.Value = strings.ToLower(attribute.Value)
		}
	}

	return parsed.String(), nil
}

// sameDN reports whether two DNs name the same directory entry.
func sameDN(a, b string) (bool, error) {
	aKey, err := normaliseDN(a)
	if err != nil {
		return false, fmt.Errorf("%q has an invalid DN: %s", a, err)
	}

	bKey, err := normaliseDN(b)
	if err != nil {
		return false, fmt.Errorf("%q has an invalid DN: %s", b, err)
	}

	return aKey == bKey, nil
}
