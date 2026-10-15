// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"sync"
	"time"
)

const (
	// connMaxIdle closes a pooled connection that has gone unused for this
	// long. It sits below the idle timeouts directories and load balancers
	// apply on their side - Active Directory's MaxConnIdleTime defaults to
	// fifteen minutes - so that a connection is retired here before it is
	// dropped there.
	connMaxIdle = time.Minute

	// connMaxLifetime bounds how long one connection is reused, so that a
	// backend which failed over to a later URL returns to the first, and a
	// change of address in DNS is picked up.
	connMaxLifetime = 10 * time.Minute

	// Expiry is checked even when no lookups visit the pool.
	connCleanupInterval = 10 * time.Second
)

// poolConnections is turned off by the tests that stand in for a lookup by
// replacing a backend's dial, so that each lookup still dials.
var poolConnections = true

// pooledConn is a bound connection, with the times the pool retires it by.
type pooledConn struct {
	conn
	opened time.Time
	used   time.Time
}

// connPool holds the idle bound connections of one backend. A connection is
// used by one lookup at a time: cancellation unblocks LDAP operations by
// closing their connection, which would cut off any other lookup sharing it.
//
// Only idle connections are capped. Those in use are already bounded by the
// lookup and refresh concurrency limits, as each lookup holds one connection
// to each backend.
type connPool struct {
	backend string

	mu     sync.Mutex
	idle   []*pooledConn // least recently used first
	size   int
	closed bool
	timer  *time.Timer

	now func() time.Time
}

func newConnPool(backend string, size int) *connPool {
	return &connPool{backend: backend, size: size, now: time.Now}
}

// get returns the most recently used idle connection that has not expired, or
// nil. Reusing the most recent keeps a small set of connections busy and lets
// the rest reach connMaxIdle when demand falls.
func (p *connPool) get() *pooledConn {
	p.mu.Lock()
	var expired []retiring
	var c *pooledConn
	for len(p.idle) > 0 {
		last := p.idle[len(p.idle)-1]
		p.idle[len(p.idle)-1] = nil
		p.idle = p.idle[:len(p.idle)-1]
		if reason := p.expiry(last); reason != "" {
			expired = append(expired, retiring{last, reason})
			continue
		}
		c = last
		break
	}
	p.mu.Unlock()

	p.retireAll(expired)
	return c
}

// put returns a connection that a lookup has finished with and left sound. It is
// closed instead when the pool is full or closed.
func (p *connPool) put(c *pooledConn) {
	p.mu.Lock()
	c.used = p.now()
	reason := p.expiry(c)
	switch {
	case p.closed:
		reason = closedShutdown
	case len(p.idle) >= p.size:
		reason = closedPoolFull
	}
	if reason != "" {
		p.mu.Unlock()
		p.retire(c, reason)
		return
	}
	p.idle = append(p.idle, c)
	if p.timer == nil {
		p.timer = time.AfterFunc(connCleanupInterval, p.reap)
	}
	p.mu.Unlock()
}

// reap checks every idle connection, including those behind a busy connection
// in the LIFO checkout order. Network cleanup happens outside the pool lock.
func (p *connPool) reap() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	var expired []retiring
	kept := p.idle[:0]
	for _, c := range p.idle {
		if reason := p.expiry(c); reason != "" {
			expired = append(expired, retiring{c, reason})
		} else {
			kept = append(kept, c)
		}
	}
	clear(p.idle[len(kept):])
	p.idle = kept
	if len(p.idle) == 0 {
		p.timer = nil
	} else {
		p.timer.Reset(connCleanupInterval)
	}
	p.mu.Unlock()
	p.retireAll(expired)
}

// close closes every idle connection, and any returned from now on.
func (p *connPool) close() {
	p.mu.Lock()
	idle := p.idle
	p.idle, p.closed = nil, true
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	p.mu.Unlock()

	for _, c := range idle {
		p.retire(c, closedShutdown)
	}
}

// expiry returns why an idle connection should be retired, or "" if it can
// still be used.
func (p *connPool) expiry(c *pooledConn) string {
	// go-ldap marks a connection closing once its reader sees the directory
	// hang up, which saves a lookup failing on it first.
	if closing, ok := c.conn.(interface{ IsClosing() bool }); ok && closing.IsClosing() {
		return closedByServer
	}

	now := p.now()
	switch {
	case now.Sub(c.opened) >= connMaxLifetime:
		return closedLifetime
	case now.Sub(c.used) >= connMaxIdle:
		return closedIdle
	}
	return ""
}

type retiring struct {
	c      *pooledConn
	reason string
}

func (p *connPool) retireAll(conns []retiring) {
	for _, r := range conns {
		p.retire(r.c, r.reason)
	}
}

// retire ends a connection the pool is done with, counting why. A healthy
// connection is unbound in the background, since that waits on the network
// and may be running on a lookup's goroutine. Any other is closed outright.
func (p *connPool) retire(c *pooledConn, reason string) {
	backendConnectionsClosed.WithLabelValues(p.backend, reason).Inc()

	if reason != closedFailed && reason != closedCanceled && reason != closedByServer {
		if r, ok := c.conn.(interface{ retire() }); ok {
			go r.retire()
			return
		}
	}
	_ = c.Close()
}
