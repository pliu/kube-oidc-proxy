// Copyright Jetstack Ltd. See LICENSE for details.
package integration

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

const (
	bindDN       = "CN=kube-oidc-proxy,OU=Service Accounts,DC=example,DC=net"
	bindPassword = "integration-test-password"
	userBase     = "OU=Users,DC=example,DC=net"
	groupBase    = "OU=Groups,DC=example,DC=net"
	userDN       = "CN=Alice,OU=Users,DC=example,DC=net"
)

// mockLDAPServer is deliberately small, but it speaks LDAP over a real TCP
// connection. It implements the bind and search operations the proxy uses to
// build its initial user-to-group mapping.
type mockLDAPServer struct {
	listener net.Listener

	mu          sync.Mutex
	binds       int
	groupSearch int
	userSearch  int
	errs        []error
	groups      []ldapGroup
	userGroups  []string
}

type ldapGroup struct {
	dn   string
	name string
}

func newMockLDAPServer(t *testing.T, groupNames ...string) *mockLDAPServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for LDAP: %s", err)
	}

	s := &mockLDAPServer{listener: listener}
	for _, name := range groupNames {
		dn := ldapGroupDN(name)
		s.groups = append(s.groups, ldapGroup{dn: dn, name: name})
		s.userGroups = append(s.userGroups, dn)
	}
	go s.serve()
	t.Cleanup(func() { _ = listener.Close() })

	return s
}

func (s *mockLDAPServer) URL() string {
	return "ldap://" + s.listener.Addr().String()
}

// AddUserToNewGroup changes what subsequent LDAP searches return. The proxy
// should not observe this until it refreshes its in-memory mapping.
func (s *mockLDAPServer) AddUserToNewGroup(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dn := ldapGroupDN(name)
	s.groups = append(s.groups, ldapGroup{dn: dn, name: name})
	s.userGroups = append(s.userGroups, dn)
}

func ldapGroupDN(name string) string {
	return fmt.Sprintf("CN=%s,%s", name, groupBase)
}

func (s *mockLDAPServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		go s.serveConn(conn)
	}
}

func (s *mockLDAPServer) serveConn(conn net.Conn) {
	defer conn.Close()

	for {
		request, err := ber.ReadPacket(conn)
		if err != nil {
			if err != io.EOF {
				s.recordError(fmt.Errorf("failed to read LDAP request: %w", err))
			}
			return
		}

		if len(request.Children) < 2 {
			s.recordError(fmt.Errorf("LDAP request has %d fields, want at least 2", len(request.Children)))
			return
		}

		messageID, ok := request.Children[0].Value.(int64)
		if !ok {
			s.recordError(fmt.Errorf("LDAP request has invalid message ID %T", request.Children[0].Value))
			return
		}

		op := request.Children[1]
		switch op.Tag {
		case goldap.ApplicationBindRequest:
			if err := s.handleBind(conn, messageID, op); err != nil {
				s.recordError(err)
				return
			}

		case goldap.ApplicationSearchRequest:
			if err := s.handleSearch(conn, messageID, op); err != nil {
				s.recordError(err)
				return
			}

		case goldap.ApplicationUnbindRequest:
			return

		default:
			s.recordError(fmt.Errorf("unexpected LDAP operation tag %d", op.Tag))
			return
		}
	}
}

func (s *mockLDAPServer) handleBind(conn net.Conn, messageID int64, request *ber.Packet) error {
	if len(request.Children) != 3 {
		return fmt.Errorf("bind request has %d fields, want 3", len(request.Children))
	}

	username, _ := request.Children[1].Value.(string)
	password := request.Children[2].Data.String()
	if username != bindDN || password != bindPassword {
		return fmt.Errorf("unexpected bind credentials for %q", username)
	}

	s.mu.Lock()
	s.binds++
	s.mu.Unlock()

	return writeLDAPMessage(conn, messageID, ldapResult(goldap.ApplicationBindResponse))
}

func (s *mockLDAPServer) handleSearch(conn net.Conn, messageID int64, request *ber.Packet) error {
	if len(request.Children) == 0 {
		return fmt.Errorf("search request has no base DN")
	}

	base, _ := request.Children[0].Value.(string)
	switch base {
	case groupBase:
		s.mu.Lock()
		s.groupSearch++
		groups := append([]ldapGroup(nil), s.groups...)
		s.mu.Unlock()

		for _, group := range groups {
			if err := writeLDAPMessage(conn, messageID, searchEntry(group.dn, map[string][]string{
				"cn": {group.name},
			})); err != nil {
				return err
			}
		}

	case userBase:
		s.mu.Lock()
		s.userSearch++
		userGroups := append([]string(nil), s.userGroups...)
		s.mu.Unlock()

		if err := writeLDAPMessage(conn, messageID, searchEntry(userDN, map[string][]string{
			"userPrincipalName": {"alice@example.com"},
			"memberOf":          userGroups,
		})); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unexpected LDAP search base %q", base)
	}

	return writeLDAPMessage(conn, messageID, ldapResult(goldap.ApplicationSearchResultDone))
}

func (s *mockLDAPServer) AssertRequests(t *testing.T, binds, groupSearches, userSearches int) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, err := range s.errs {
		t.Error(err)
	}
	if s.binds != binds {
		t.Errorf("LDAP bind count = %d, want %d", s.binds, binds)
	}
	if s.groupSearch != groupSearches {
		t.Errorf("LDAP group search count = %d, want %d", s.groupSearch, groupSearches)
	}
	if s.userSearch != userSearches {
		t.Errorf("LDAP user search count = %d, want %d", s.userSearch, userSearches)
	}
}

func (s *mockLDAPServer) recordError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs = append(s.errs, err)
}

func writeLDAPMessage(w io.Writer, messageID int64, operation *ber.Packet) error {
	message := ber.NewSequence("LDAP Message")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger,
		messageID, "Message ID"))
	message.AppendChild(operation)

	_, err := w.Write(message.Bytes())
	return err
}

func ldapResult(applicationTag ber.Tag) *ber.Packet {
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, applicationTag, nil, "LDAP Result")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated,
		0, "Result Code"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		"", "Matched DN"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		"", "Diagnostic Message"))
	return result
}

func searchEntry(dn string, attributes map[string][]string) *ber.Packet {
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		goldap.ApplicationSearchResultEntry, nil, "Search Result Entry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		dn, "Object Name"))

	attributeList := ber.NewSequence("Attributes")
	for name, values := range attributes {
		attribute := ber.NewSequence("Attribute")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
			name, "Attribute Name"))

		valueSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
		for _, value := range values {
			valueSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
				value, "Attribute Value"))
		}

		attribute.AppendChild(valueSet)
		attributeList.AppendChild(attribute)
	}

	entry.AppendChild(attributeList)
	return entry
}
