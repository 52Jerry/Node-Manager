package socks

import (
	"context"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const authNegotiationTimeout = 15 * time.Second

// This wraps only the upstream TCP authentication handshake. The existing
// socks.Client still owns its protocol, destination and UDP framing behavior.
type authBreakerDialer struct {
	N.Dialer
	breaker          *authBreaker
	identity         authCircuitIdentity
	server           M.Socksaddr
	handshakeTimeout time.Duration
}

func (d *authBreakerDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP || destination != d.server {
		return d.Dialer.DialContext(ctx, network, destination)
	}
	d.breaker.startMaintenance()
	permit, err := d.breaker.acquire(ctx, d.identity)
	if err != nil {
		return nil, err
	}
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		permit.finish(authUnknown)
		return nil, err
	}
	if permit == nil {
		return conn, nil
	}
	timeout := d.handshakeTimeout
	if timeout == 0 {
		timeout = authNegotiationTimeout
	}
	wrapped := &authObservedConn{Conn: conn, permit: permit}
	wrapped.start(ctx, timeout)
	return wrapped, nil
}

type authObservedConn struct {
	net.Conn
	mu          sync.Mutex
	permit      *authPermit
	frame       [4]byte
	frameBytes  int
	done        bool
	timer       *time.Timer
	stopContext func() bool
}

func (c *authObservedConn) start(ctx context.Context, timeout time.Duration) {
	timer := time.AfterFunc(timeout, func() { _ = c.Close() })
	stopContext := context.AfterFunc(ctx, func() { _ = c.Close() })
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		timer.Stop()
		stopContext()
		return
	}
	c.timer = timer
	c.stopContext = stopContext
	c.mu.Unlock()
}

func (c *authObservedConn) finish(outcome authOutcome) {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	c.done = true
	timer, stopContext := c.timer, c.stopContext
	c.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	if stopContext != nil {
		stopContext()
	}
	c.permit.finish(outcome)
}

func (c *authObservedConn) observe(data []byte) {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	for _, value := range data {
		if c.frameBytes == len(c.frame) {
			break
		}
		c.frame[c.frameBytes] = value
		c.frameBytes++
		if c.frameBytes == 2 {
			if c.frame[0] != 5 {
				c.mu.Unlock()
				c.finish(authUnknown)
				return
			}
			if c.frame[1] == 0 { // Server explicitly accepts without auth.
				c.mu.Unlock()
				c.finish(authAccepted)
				return
			}
			if c.frame[1] != 2 {
				c.mu.Unlock()
				c.finish(authUnknown)
				return
			}
		}
		if c.frameBytes == 4 {
			outcome := authUnknown
			// RFC1929 version 1 and a nonzero result explicitly identify an
			// authentication rejection. EOF and SOCKS CONNECT reply errors do not.
			if c.frame[2] == 1 {
				outcome = authAccepted
				if c.frame[3] != 0 {
					outcome = authRejected
				}
			}
			c.mu.Unlock()
			c.finish(outcome)
			return
		}
	}
	c.mu.Unlock()
}

func (c *authObservedConn) Read(data []byte) (int, error) {
	count, err := c.Conn.Read(data)
	if count != 0 {
		c.observe(data[:count])
	}
	if err != nil {
		c.finish(authUnknown)
	}
	return count, err
}

func (c *authObservedConn) Write(data []byte) (int, error) {
	count, err := c.Conn.Write(data)
	if err != nil {
		c.finish(authUnknown)
	}
	return count, err
}

func (c *authObservedConn) Close() error {
	c.finish(authUnknown)
	return c.Conn.Close()
}

// Once auth is observed the data plane can unwrap to the original connection,
// preserving native read-waiters, vectorized writes and zero-copy capabilities.
func (c *authObservedConn) ReaderReplaceable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.done
}

func (c *authObservedConn) WriterReplaceable() bool { return true }
func (c *authObservedConn) Upstream() any           { return c.Conn }
