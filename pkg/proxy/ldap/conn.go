// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
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
	Search(req *goldap.SearchRequest) (*goldap.SearchResult, error)
	Close() error
}

// retireTimeout bounds unbinding a connection the pool retires. A variable
// so that tests need not wait it out.
var retireTimeout = 5 * time.Second

// socketConn interrupts network I/O before asking go-ldap to stop its message
// processor. go-ldap's Close waits for that processor, which can itself be
// blocked writing to the socket.
type socketConn struct {
	*goldap.Conn
	socket net.Conn
	once   sync.Once
	err    error
}

func (c *socketConn) Close() error {
	c.once.Do(func() {
		c.err = c.socket.Close()
		_ = c.Conn.Close()
	})
	return c.err
}

// retire ends a healthy idle connection as a client should: an LDAP unbind,
// then TLS close_notify on an LDAPS or StartTLS connection. The deadline
// bounds both, in case the directory has stopped reading. Close is the way to
// end a connection something may be blocked on. It returns within about twice
// retireTimeout, and runs in the background.
func (c *socketConn) retire() {
	c.once.Do(func() {
		_ = c.socket.SetDeadline(time.Now().Add(retireTimeout))
		// go-ldap never finishes an unbind request, so when writing one fails
		// its message processor waits on a reader that is not there, and Close
		// waits on the processor. A request timeout bounds both waits.
		c.Conn.SetTimeout(retireTimeout)
		// Unbind closes the connection once it has sent the request, and
		// leaves it open if it could not.
		_ = c.Conn.Unbind()
		_ = c.Conn.Close()
		c.err = c.socket.Close()
	})
}

// timeLimit is the timeout as the seconds a search request carries, so that a
// directory which is still listening gives up on its own and answers with a
// result code before cancellation closes the connection. It is
// rounded up, since a limit of zero is what the protocol uses for no limit.
func (b *backend) timeLimit() int {
	seconds := int((b.config.Timeout.Duration() + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}

	return seconds
}

// withConn applies one deadline to dialing, binding, and searching, running fn
// on a pooled connection when there is one. Closing the connection on
// cancellation unblocks LDAP operations that have no context API.
//
// The directory may have dropped a pooled connection since it was last used,
// so a lookup the connection failed under is retried once on a fresh one. fn
// only reads the directory, so running it again is safe. A lookup that failed
// for any other reason, such as a result code the directory answered with, is
// not retried: it would fail the same way again.
func (b *backend) withConn(ctx context.Context, fn func(conn) error) error {
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout.Duration())
	defer cancel()

	if c := b.pool.get(); c != nil {
		broken, err := b.use(ctx, c, fn)
		if !broken || ctx.Err() != nil {
			return contextErr(ctx, err)
		}
	}

	c, err := b.connect(ctx)
	if err == nil {
		_, err = b.use(ctx, c, fn)
	}
	return contextErr(ctx, err)
}

// use runs fn on c, reporting whether c broke, and otherwise returns c to the
// pool, whether fn succeeded or not. A connection closed by cancellation, or
// one an operation failed on without an answer from the directory, is left
// closed: what state an interrupted exchange left it in is unknown.
func (b *backend) use(ctx context.Context, c *pooledConn, fn func(conn) error) (bool, error) {
	watched := &watchedConn{conn: c.conn}
	stop := context.AfterFunc(ctx, func() { b.pool.retire(c, closedCanceled) })
	err := fn(watched)
	if !stop() {
		// Cancellation has closed the connection.
		return true, err
	}
	if watched.broken {
		b.pool.retire(c, closedFailed)
		return true, err
	}
	b.pool.put(c)
	return false, err
}

// watchedConn records whether a search on the connection failed in a way that
// leaves the connection in doubt. A lookup can fail on a sound connection,
// when the directory answers with a result code or the lookup rejects what it
// found, and that connection is still fit to reuse.
type watchedConn struct {
	conn
	broken bool
}

func (c *watchedConn) Search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	res, err := c.conn.Search(req)
	if err != nil && leavesConnInDoubt(err) {
		c.broken = true
	}
	return res, err
}

// leavesConnInDoubt reports whether err is a connection that failed, closed,
// or carried a message go-ldap could not make sense of. Any other LDAP error
// is a result code the directory answered with, or one of go-ldap's own, such
// as a filter that does not compile, raised before anything was sent.
func leavesConnInDoubt(err error) bool {
	var ldapErr *goldap.Error
	if !errors.As(err, &ldapErr) {
		return true
	}
	switch ldapErr.ResultCode {
	case goldap.ErrorNetwork, goldap.ErrorUnexpectedMessage, goldap.ErrorUnexpectedResponse:
		return true
	}
	return false
}

// contextErr reports a canceled or expired context in place of the error it
// caused, such as that of an operation on the connection it closed.
func contextErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// connect dials the configured URLs in order, returning the first connection
// that can be established and bound.
//
// Each connection is closed on cancellation as soon as it exists, since a
// directory that accepts the connection and then never answers the bind hangs
// just as thoroughly as one that never answers a search. The connection
// returned is no longer tied to ctx, so that it can outlive this lookup in the
// pool.
func (b *backend) connect(ctx context.Context) (*pooledConn, error) {
	var errs []string

	for _, rawURL := range b.config.URLs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, err := b.dialURL(ctx, rawURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", rawURL, err))
			continue
		}

		closeConn := sync.OnceFunc(func() { _ = c.Close() })
		stop := context.AfterFunc(ctx, closeConn)
		fail := func() {
			stop()
			closeConn()
		}

		if b.config.StartTLS {
			tlsConfig, err := tlsConfigForURL(b.tlsConfig, rawURL)
			if err != nil {
				fail()
				errs = append(errs, fmt.Sprintf("%s: StartTLS setup failed: %s", rawURL, err))
				continue
			}

			if err := c.StartTLS(tlsConfig); err != nil {
				fail()
				errs = append(errs, fmt.Sprintf("%s: StartTLS failed: %s", rawURL, err))
				continue
			}
		}

		// An empty bind DN leaves the connection anonymous.
		if b.config.BindDN != "" {
			if err := c.Bind(b.config.BindDN, b.bindPassword); err != nil {
				fail()
				errs = append(errs, fmt.Sprintf("%s: bind failed: %s", rawURL, err))
				continue
			}
		}

		if !stop() {
			// Cancellation has closed the connection.
			return nil, ctx.Err()
		}
		backendConnections.WithLabelValues(b.config.Name).Inc()
		now := b.pool.now()
		return &pooledConn{conn: c, opened: now, used: now}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("unable to connect to any server [%s]", strings.Join(errs, ", "))
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
	// Cancellation cannot close a connection that does not exist yet, so the
	// dial carries its own bound. go-ldap otherwise applies a package level
	// default of 60s, which no configuration can move.
	dialer := &net.Dialer{Timeout: b.config.Timeout.Duration()}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, goldap.NewError(goldap.ErrorNetwork, err)
	}
	network, address := "tcp", ""
	port := u.Port()
	switch u.Scheme {
	case "ldap", "ldaps", "cldap":
		if port == "" {
			port = goldap.DefaultLdapPort
			if u.Scheme == "ldaps" {
				port = goldap.DefaultLdapsPort
			}
		}
		address = net.JoinHostPort(u.Hostname(), port)
		if u.Scheme == "cldap" {
			network = "udp"
		}
	case "ldapi":
		network, address = "unix", u.Path
		if address == "" || address == "/" {
			address = "/var/run/slapd/ldapi"
		}
	default:
		return nil, goldap.NewError(goldap.ErrorNetwork, fmt.Errorf("unknown scheme %q", u.Scheme))
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.config.Timeout.Duration())
	defer cancel()
	socket, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, goldap.NewError(goldap.ErrorNetwork, err)
	}
	var transport net.Conn = socket
	if u.Scheme == "ldaps" {
		config := b.tlsConfig.Clone()
		if config.ServerName == "" {
			config.ServerName = u.Hostname()
		}
		tlsConn := tls.Client(socket, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = socket.Close()
			return nil, goldap.NewError(goldap.ErrorNetwork, err)
		}
		transport = tlsConn
	}
	c := goldap.NewConn(transport, u.Scheme == "ldaps")
	c.Start()
	return &socketConn{Conn: c, socket: socket}, nil
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

// The dialer itself has a socket timeout. A canceled caller returns promptly;
// a connection arriving after cancellation is closed rather than leaked.
func (b *backend) dialURL(ctx context.Context, url string) (conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type result struct {
		c   conn
		err error
	}
	ready := make(chan result)
	go func() {
		c, err := b.dial(url)
		select {
		case ready <- result{c, err}:
		case <-ctx.Done():
			if c != nil {
				c.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ready:
		return r.c, r.err
	}
}
