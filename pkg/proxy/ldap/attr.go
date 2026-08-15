// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"fmt"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// attributeValues returns the values of the named attribute of an entry, along
// with any options the directory attached to it.
//
// An attribute description is matched by name rather than compared as a whole,
// because a directory is free to answer with a description that is not the one
// that was asked for. Active Directory substitutes "memberOf;range=0-1499" for
// a truncated "memberOf", and directories differ on the case they echo back -
// 389 Directory Server, and so FreeIPA, answers in the case its schema
// defines. Entry.GetAttributeValues compares the description exactly, so it
// silently finds nothing in either case.
func attributeValues(entry *goldap.Entry, name string) (values []string, options string, found bool) {
	for _, attribute := range entry.Attributes {
		base, options := splitAttributeDescription(attribute.Name)
		if strings.EqualFold(base, name) {
			return attribute.Values, options, true
		}
	}

	return nil, "", false
}

// attributeValue returns the first value of the named attribute, or "".
func attributeValue(entry *goldap.Entry, name string) string {
	values, _, _ := attributeValues(entry, name)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// splitAttributeDescription splits an attribute description into its name and
// its options: the "memberOf" and "range=0-1499" of "memberOf;range=0-1499".
func splitAttributeDescription(description string) (name, options string) {
	if i := strings.IndexByte(description, ';'); i >= 0 {
		return description[:i], description[i+1:]
	}

	return description, ""
}

// memberOfChunk is the memberOf values of an entry, together with where the
// directory truncated them.
type memberOfChunk struct {
	dns []string

	// next is the index the values continue from, or -1 when the directory
	// returned all of them.
	next int
}

// memberOfFrom reads the memberOf values of an entry, honouring the range
// option a directory truncates them with.
func memberOfFrom(entry *goldap.Entry) (memberOfChunk, error) {
	values, options, found := attributeValues(entry, memberOfAttribute)
	if !found {
		// An entry that is a member of nothing, or one asked for a window
		// past the end of its memberOf.
		return memberOfChunk{next: -1}, nil
	}

	next, err := parseRangeOption(options)
	if err != nil {
		return memberOfChunk{}, fmt.Errorf("entry %q: %s", entry.DN, err)
	}

	return memberOfChunk{dns: values, next: next}, nil
}

// parseRangeOption returns the index the values of a ranged attribute continue
// from, or -1 when the attribute is not ranged or this is the last window of
// it. The option is "range=0-1499" for a truncated attribute and
// "range=3000-*" for the window that completes it.
func parseRangeOption(options string) (int, error) {
	for _, option := range strings.Split(options, ";") {
		if len(option) < len(rangeOption) || !strings.EqualFold(option[:len(rangeOption)], rangeOption) {
			continue
		}

		bounds := option[len(rangeOption):]

		i := strings.IndexByte(bounds, '-')
		if i < 0 {
			return 0, fmt.Errorf("malformed range option %q", option)
		}

		// The window that completes the attribute ends in "*" rather than in
		// the index of its last value.
		last := bounds[i+1:]
		if last == "*" {
			return -1, nil
		}

		end, err := strconv.Atoi(last)
		if err != nil {
			return 0, fmt.Errorf("malformed range option %q", option)
		}

		return end + 1, nil
	}

	return -1, nil
}

// memberOfDNs returns every group DN of an entry, collecting the rest of them
// a window at a time if the directory truncated the attribute.
//
// Active Directory caps memberOf at MaxValRange, 1500 values by default, and
// expects a client that wants the rest to ask for them explicitly. Ignoring
// that leaves the users in the most groups - who tend to be the ones with the
// most access - holding no groups at all, since the truncated attribute comes
// back under a description that does not match the one asked for.
//
// 389 Directory Server, and so FreeIPA, returns every value and never takes
// this path.
func (b *backend) memberOfDNs(c conn, entry *goldap.Entry) ([]string, error) {
	chunk, err := memberOfFrom(entry)
	if err != nil {
		return nil, err
	}

	dns := chunk.dns

	for requests := 0; chunk.next >= 0; requests++ {
		if requests == maxRangeRequests {
			return nil, fmt.Errorf("gave up collecting the %s of %q after %d requests",
				memberOfAttribute, entry.DN, maxRangeRequests)
		}

		from := chunk.next

		chunk, err = b.searchMemberOfRange(c, entry.DN, from)
		if err != nil {
			return nil, err
		}

		dns = append(dns, chunk.dns...)

		// A directory that answers a window without moving past it would
		// otherwise be asked the same question until the bound above is hit.
		if chunk.next >= 0 && chunk.next <= from {
			return nil, fmt.Errorf("directory did not advance the %s range of %q past %d",
				memberOfAttribute, entry.DN, from)
		}
	}

	return dns, nil
}

// searchMemberOfRange reads the memberOf values of one entry from the given
// index onwards.
func (b *backend) searchMemberOfRange(c conn, dn string, from int) (memberOfChunk, error) {
	attribute := fmt.Sprintf("%s;%s%d-*", memberOfAttribute, rangeOption, from)

	req := goldap.NewSearchRequest(dn, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, b.timeLimit(), false, "(objectClass=*)", []string{attribute}, nil)

	res, err := c.Search(req)
	if err != nil {
		return memberOfChunk{}, fmt.Errorf("failed to read %q of %q: %s", attribute, dn, err)
	}

	if len(res.Entries) != 1 {
		return memberOfChunk{}, fmt.Errorf("failed to read %q of %q: expected one entry, got %d",
			attribute, dn, len(res.Entries))
	}

	return memberOfFrom(res.Entries[0])
}
