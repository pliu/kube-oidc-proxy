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

// closeOnCancel keeps connection cleanup active through bind and search. The
// returned cleanup stops cancellation handling and closes the connection once,
// even if cancellation and normal completion race.
func closeOnCancel(ctx context.Context, c conn) func() {
	closeConn := sync.OnceFunc(func() { _ = c.Close() })
	stop := context.AfterFunc(ctx, closeConn)
	return func() {
		stop()
		closeConn()
	}
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

// withConn applies one deadline to dialing, binding, and searching. Closing the
// connection on cancellation unblocks LDAP operations that have no context API.
func (b *backend) withConn(ctx context.Context, fn func(conn) error) error {
	ctx, cancel := context.WithTimeout(ctx, b.config.Timeout.Duration())
	defer cancel()
	c, cleanup, err := b.connect(ctx)
	if err == nil {
		defer cleanup()
		err = fn(c)
	}
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
// just as thoroughly as one that never answers a search.
func (b *backend) connect(ctx context.Context) (conn, func(), error) {
	var errs []string

	for _, rawURL := range b.config.URLs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		c, err := b.dialURL(ctx, rawURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", rawURL, err))
			continue
		}

		cleanup := closeOnCancel(ctx, c)
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, nil, err
		}

		if b.config.StartTLS {
			tlsConfig, err := tlsConfigForURL(b.tlsConfig, rawURL)
			if err != nil {
				cleanup()
				errs = append(errs, fmt.Sprintf("%s: StartTLS setup failed: %s", rawURL, err))
				continue
			}

			if err := c.StartTLS(tlsConfig); err != nil {
				cleanup()
				errs = append(errs, fmt.Sprintf("%s: StartTLS failed: %s", rawURL, err))
				continue
			}
		}

		// An empty bind DN leaves the connection anonymous.
		if b.config.BindDN != "" {
			if err := c.Bind(b.config.BindDN, b.bindPassword); err != nil {
				cleanup()
				errs = append(errs, fmt.Sprintf("%s: bind failed: %s", rawURL, err))
				continue
			}
		}

		return c, cleanup, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("unable to connect to any server [%s]", strings.Join(errs, ", "))
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
