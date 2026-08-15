// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// conn is the subset of *goldap.Conn used by a backend, so that the search
// behaviour can be exercised without a live directory.
type conn interface {
	StartTLS(*tls.Config) error
	Bind(username, password string) error
	SearchWithPaging(req *goldap.SearchRequest, pagingSize uint32) (*goldap.SearchResult, error)
	Search(req *goldap.SearchRequest) (*goldap.SearchResult, error)
	Close() error
}

// watchdog closes a connection that a backend has not finished with in time.
//
// go-ldap reads a response off a channel that nothing else ever writes to if
// the directory goes quiet, and neither Conn.SetTimeout nor the request time
// limit reaches that: the first bounds the delivery of a response that did
// arrive, the second is enforced by a server that is still listening. Closing
// the connection is what unblocks the read, so that is what this does.
type watchdog struct {
	timeout time.Duration
	timer   *time.Timer

	mu sync.Mutex
	// c is the connection to close, once there is one to close.
	c conn
	// fired records that the timeout expired, so that whatever error the
	// closed connection produces can be reported as the timeout it is.
	fired bool
}

func newWatchdog(timeout time.Duration) *watchdog {
	w := &watchdog{timeout: timeout}
	w.timer = time.AfterFunc(timeout, w.fire)

	return w
}

// watch hands the watchdog the connection to close, closing it immediately if
// the timeout has already expired.
func (w *watchdog) watch(c conn) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.c = c

	if w.fired {
		c.Close()
	}
}

// forget drops a connection the backend has closed itself, so that a later
// timeout cannot close a connection this backend no longer owns.
func (w *watchdog) forget() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.c = nil
}

func (w *watchdog) fire() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.fired = true

	if w.c != nil {
		w.c.Close()
	}
}

func (w *watchdog) stop() {
	w.timer.Stop()
}

// wrap reports an error as the timeout that caused it, when it was. What
// go-ldap returns from a connection closed under it says nothing about why.
func (w *watchdog) wrap(err error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err == nil || !w.fired {
		return err
	}

	return fmt.Errorf("timed out after %s: %s", w.timeout, err)
}

// timeLimit is the timeout as the seconds a search request carries, so that a
// directory which is still listening gives up on its own and answers with a
// result code, rather than being cut off mid sentence by the watchdog. It is
// rounded up, since a limit of zero is what the protocol uses for no limit.
func (b *backend) timeLimit() int {
	seconds := int((b.config.Timeout.Duration() + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}

	return seconds
}

// withConn dials the backend, runs fn against the bound connection, and
// closes it. A directory that goes quiet is cut off by the watchdog, and the
// resulting error is reported as the timeout it is.
func (b *backend) withConn(fn func(conn) error) error {
	// A directory that accepts a connection and then stops answering would
	// otherwise hold a refresh here for as long as the process runs: go-ldap
	// waits for a response on a channel with no deadline of its own, so
	// closing the connection under it is the only way back out.
	w := newWatchdog(b.config.Timeout.Duration())
	defer w.stop()

	c, err := b.connect(w)
	if err != nil {
		return w.wrap(err)
	}
	defer c.Close()

	return w.wrap(fn(c))
}

// connect dials the configured URLs in order, returning the first connection
// that can be established and bound.
//
// Each connection is handed to the watchdog as soon as it exists, since a
// directory that accepts the connection and then never answers the bind hangs
// just as thoroughly as one that never answers a search.
func (b *backend) connect(w *watchdog) (conn, error) {
	var errs []string

	for _, rawURL := range b.config.URLs {
		c, err := b.dial(rawURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", rawURL, err))
			continue
		}

		w.watch(c)

		if b.config.StartTLS {
			tlsConfig, err := tlsConfigForURL(b.tlsConfig, rawURL)
			if err != nil {
				abandon(c, w)
				errs = append(errs, fmt.Sprintf("%s: StartTLS setup failed: %s", rawURL, err))
				continue
			}

			if err := c.StartTLS(tlsConfig); err != nil {
				abandon(c, w)
				errs = append(errs, fmt.Sprintf("%s: StartTLS failed: %s", rawURL, err))
				continue
			}
		}

		// An empty bind DN leaves the connection anonymous.
		if b.config.BindDN != "" {
			if err := c.Bind(b.config.BindDN, b.bindPassword); err != nil {
				abandon(c, w)
				errs = append(errs, fmt.Sprintf("%s: bind failed: %s", rawURL, err))
				continue
			}
		}

		return c, nil
	}

	return nil, fmt.Errorf("unable to connect to any server [%s]", strings.Join(errs, ", "))
}

// abandon closes a connection this backend is giving up on, so the watchdog
// cannot close it again after it has been released.
func abandon(c conn, w *watchdog) {
	c.Close()
	w.forget()
}

// tlsConfigForURL gives a StartTLS handshake the server name it cannot infer
// from an already-established TCP connection. An LDAPS dial gets this from
// tls.DialWithDialer, but tls.Client (which go-ldap uses for StartTLS) does not.
func tlsConfigForURL(base *tls.Config, rawURL string) (*tls.Config, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, errors.New("URL has no hostname for certificate verification")
	}

	config := base.Clone()
	config.ServerName = hostname

	return config, nil
}

func (b *backend) dialLDAP(rawURL string) (conn, error) {
	// The watchdog cannot close a connection that does not exist yet, so the
	// dial carries its own bound. go-ldap otherwise applies a package level
	// default of 60s, which no configuration can move.
	dialer := &net.Dialer{Timeout: b.config.Timeout.Duration()}

	return goldap.DialURL(rawURL, goldap.DialWithTLSConfig(b.tlsConfig), goldap.DialWithDialer(dialer))
}

func tlsConfigFor(config *BackendConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipTLSVerify,
	}

	if config.CAFile == "" {
		return tlsConfig, nil
	}

	ca, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("backend %q: failed to read caFile %q: %s", config.Name, config.CAFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("backend %q: no certificates found in caFile %q", config.Name, config.CAFile)
	}
	tlsConfig.RootCAs = pool

	return tlsConfig, nil
}
