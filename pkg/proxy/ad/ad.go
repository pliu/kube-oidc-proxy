// Copyright Jetstack Ltd. See LICENSE for details.

// Package ad augments the groups of an authenticated user with the groups
// they are a member of in an Active Directory (or any LDAP v3) backend.
//
// The full user -> group mapping is built up front and held in memory. It is
// rebuilt on an interval, or on demand, and swapped in atomically so that
// in flight requests always read a complete, consistent mapping.
package ad

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
	"k8s.io/klog/v2"
)

const (
	// pageSize is the LDAP paging size used for searches. 1000 is the default
	// MaxPageSize of an Active Directory domain controller.
	pageSize = 1000

	// memberOfAttribute holds the DNs of the groups an entry belongs to.
	memberOfAttribute = "memberOf"
)

var (
	ErrNoURL             = errors.New("no Active Directory URL configured")
	ErrNoUserSearchBase  = errors.New("no Active Directory user search base configured")
	ErrNoGroupSearchBase = errors.New("no Active Directory group search base configured")
)

type Config struct {
	URLs                  []string
	BindDN                string
	BindPassword          string
	CAFile                string
	InsecureSkipTLSVerify bool
	StartTLS              bool

	UserSearchBases   []string
	UserFilter        string
	UsernameAttribute string

	GroupSearchBases   []string
	GroupFilter        string
	GroupNameAttribute string
	GroupPrefix        string

	RefreshInterval       time.Duration
	FallbackToTokenGroups bool

	// RefreshUsers is the set of users allowed to trigger a refresh. If empty,
	// any authenticated user may trigger one.
	RefreshUsers []string

	// UsernamePrefix is the OIDC username prefix. It is stripped from the
	// username of a request before looking it up in the directory, so that
	// the directory can be keyed on the raw attribute value.
	UsernamePrefix string
}

// conn is the subset of *ldap.Conn used by the Directory, so that the search
// behaviour can be exercised without a live directory.
type conn interface {
	StartTLS(*tls.Config) error
	Bind(username, password string) error
	SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
	Close() error
}

// Stats describes the state of the currently active mapping.
type Stats struct {
	Users       int       `json:"users"`
	Groups      int       `json:"groups"`
	LastRefresh time.Time `json:"lastRefresh"`
	Duration    string    `json:"duration"`
}

type Directory struct {
	config    *Config
	tlsConfig *tls.Config

	// mapping is the active username -> groups mapping. It is only ever
	// replaced, never mutated, so readers need no locking.
	mapping atomic.Pointer[map[string][]string]
	stats   atomic.Pointer[Stats]

	// refreshMu serialises refreshes so that a burst of requests to the
	// refresh endpoint cannot fan out into a burst of directory searches.
	refreshMu sync.Mutex

	// refreshUsers holds the lower cased names of the users allowed to trigger
	// a refresh. Empty means any authenticated user may.
	refreshUsers map[string]struct{}

	dial func(url string) (conn, error)
}

func New(config *Config) (*Directory, error) {
	if len(config.URLs) == 0 {
		return nil, ErrNoURL
	}
	if len(config.UserSearchBases) == 0 {
		return nil, ErrNoUserSearchBase
	}
	if len(config.GroupSearchBases) == 0 {
		return nil, ErrNoGroupSearchBase
	}

	tlsConfig, err := tlsConfigFor(config)
	if err != nil {
		return nil, err
	}

	refreshUsers := make(map[string]struct{}, len(config.RefreshUsers))
	for _, username := range config.RefreshUsers {
		refreshUsers[strings.ToLower(username)] = struct{}{}
	}

	d := &Directory{
		config:       config,
		tlsConfig:    tlsConfig,
		refreshUsers: refreshUsers,
	}
	d.dial = d.dialLDAP

	empty := make(map[string][]string)
	d.mapping.Store(&empty)
	d.stats.Store(&Stats{})

	return d, nil
}

// Run builds the initial mapping and then keeps it refreshed until stopCh is
// closed. The initial refresh is synchronous: starting to serve requests with
// an empty mapping would silently strip every user of their groups.
func (d *Directory) Run(stopCh <-chan struct{}) error {
	if err := d.Refresh(); err != nil {
		return fmt.Errorf("failed to build initial Active Directory mapping: %s", err)
	}

	go func() {
		ticker := time.NewTicker(d.config.RefreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return

			case <-ticker.C:
				if err := d.Refresh(); err != nil {
					// Keep serving the previous mapping rather than failing
					// every request while the directory is unreachable.
					klog.Errorf("failed to refresh Active Directory mapping, keeping previous mapping: %s", err)
				}
			}
		}
	}()

	return nil
}

// Refresh rebuilds the user -> group mapping and atomically swaps it in. The
// previous mapping is left in place if the rebuild fails.
func (d *Directory) Refresh() error {
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()

	start := time.Now()

	mapping, groups, err := d.build()
	if err != nil {
		return err
	}

	d.mapping.Store(&mapping)
	d.stats.Store(&Stats{
		Users:       len(mapping),
		Groups:      groups,
		LastRefresh: start,
		Duration:    time.Since(start).String(),
	})

	klog.V(2).Infof("refreshed Active Directory mapping: %d users, %d groups (%s)",
		len(mapping), groups, time.Since(start))

	return nil
}

// Groups returns the directory groups of the given username. The second return
// value reports whether the user was found in the directory at all - a user
// that exists but is in none of the configured groups returns an empty slice
// and true.
func (d *Directory) Groups(username string) ([]string, bool) {
	mapping := *d.mapping.Load()

	if groups, ok := mapping[strings.ToLower(username)]; ok {
		return groups, true
	}

	// The username of the request carries the OIDC username prefix, whereas
	// the directory is keyed on the bare attribute value.
	if p := d.config.UsernamePrefix; p != "" && strings.HasPrefix(username, p) {
		groups, ok := mapping[strings.ToLower(strings.TrimPrefix(username, p))]
		return groups, ok
	}

	return nil, false
}

// CanRefresh reports whether the given user is allowed to trigger a refresh.
// With no allowed users configured, any user may - the endpoint already sits
// behind authentication.
func (d *Directory) CanRefresh(username string) bool {
	if len(d.refreshUsers) == 0 {
		return true
	}

	if _, ok := d.refreshUsers[strings.ToLower(username)]; ok {
		return true
	}

	// Allow the allowed users to be given either as they appear in the token
	// or without the OIDC username prefix, matching how users are looked up in
	// the directory.
	if p := d.config.UsernamePrefix; p != "" && strings.HasPrefix(username, p) {
		_, ok := d.refreshUsers[strings.ToLower(strings.TrimPrefix(username, p))]
		return ok
	}

	return false
}

// FallbackToTokenGroups reports whether users missing from the directory keep
// the groups from their token.
func (d *Directory) FallbackToTokenGroups() bool {
	return d.config.FallbackToTokenGroups
}

func (d *Directory) Stats() *Stats {
	return d.stats.Load()
}

// build searches the directory and returns a username -> groups mapping,
// along with the number of distinct groups that were considered.
func (d *Directory) build() (map[string][]string, int, error) {
	c, err := d.connect()
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()

	// Only groups that live under one of the configured search bases are
	// pulled, so the mapping is restricted to the intended part of the tree.
	groupNames, err := d.searchGroups(c)
	if err != nil {
		return nil, 0, err
	}

	mapping, err := d.searchUsers(c, groupNames)
	if err != nil {
		return nil, 0, err
	}

	return mapping, len(groupNames), nil
}

// searchGroups returns a mapping of normalised group DN -> group name for
// every group under the configured group search bases.
func (d *Directory) searchGroups(c conn) (map[string]string, error) {
	groupNames := make(map[string]string)

	for _, base := range d.config.GroupSearchBases {
		req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, d.config.GroupFilter, []string{d.config.GroupNameAttribute}, nil)

		res, err := c.SearchWithPaging(req, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to search groups in %q: %s", base, err)
		}

		for _, entry := range res.Entries {
			name := entry.GetAttributeValue(d.config.GroupNameAttribute)
			if name == "" {
				klog.V(4).Infof("skipping group %q with no %q attribute", entry.DN, d.config.GroupNameAttribute)
				continue
			}

			groupNames[normaliseDN(entry.DN)] = d.config.GroupPrefix + name
		}
	}

	return groupNames, nil
}

// searchUsers returns a mapping of lower cased username -> group names, using
// the memberOf attribute of each user filtered down to the known groups.
func (d *Directory) searchUsers(c conn, groupNames map[string]string) (map[string][]string, error) {
	mapping := make(map[string][]string)

	for _, base := range d.config.UserSearchBases {
		req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, d.config.UserFilter,
			[]string{d.config.UsernameAttribute, memberOfAttribute}, nil)

		res, err := c.SearchWithPaging(req, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to search users in %q: %s", base, err)
		}

		for _, entry := range res.Entries {
			username := entry.GetAttributeValue(d.config.UsernameAttribute)
			if username == "" {
				klog.V(4).Infof("skipping user %q with no %q attribute", entry.DN, d.config.UsernameAttribute)
				continue
			}

			groups := make([]string, 0)
			for _, dn := range entry.GetAttributeValues(memberOfAttribute) {
				if name, ok := groupNames[normaliseDN(dn)]; ok {
					groups = append(groups, name)
				}
			}

			// The mapping is shared by every request, so clip the slice to its
			// length: a caller appending to it then gets a copy rather than
			// writing into spare capacity that other requests can see.
			mapping[strings.ToLower(username)] = groups[:len(groups):len(groups)]
		}
	}

	return mapping, nil
}

// connect dials the configured URLs in order, returning the first connection
// that can be established and bound.
func (d *Directory) connect() (conn, error) {
	var errs []string

	for _, url := range d.config.URLs {
		c, err := d.dial(url)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", url, err))
			continue
		}

		if d.config.StartTLS {
			if err := c.StartTLS(d.tlsConfig); err != nil {
				c.Close()
				errs = append(errs, fmt.Sprintf("%s: StartTLS failed: %s", url, err))
				continue
			}
		}

		// An empty bind DN leaves the connection anonymous.
		if d.config.BindDN != "" {
			if err := c.Bind(d.config.BindDN, d.config.BindPassword); err != nil {
				c.Close()
				errs = append(errs, fmt.Sprintf("%s: bind failed: %s", url, err))
				continue
			}
		}

		return c, nil
	}

	return nil, fmt.Errorf("unable to connect to any Active Directory server [%s]", strings.Join(errs, ", "))
}

func (d *Directory) dialLDAP(url string) (conn, error) {
	return ldap.DialURL(url, ldap.DialWithTLSConfig(d.tlsConfig))
}

func tlsConfigFor(config *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipTLSVerify,
	}

	if config.CAFile == "" {
		return tlsConfig, nil
	}

	ca, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read Active Directory CA file %q: %s", config.CAFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("no certificates found in Active Directory CA file %q", config.CAFile)
	}
	tlsConfig.RootCAs = pool

	return tlsConfig, nil
}

// normaliseDN makes DNs comparable across the group and memberOf attributes,
// which are not guaranteed to agree on case or spacing.
func normaliseDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}

	return strings.ToLower(strings.Join(parts, ","))
}
