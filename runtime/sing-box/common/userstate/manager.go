// Package userstate coordinates credential publication with authenticated sessions.
package userstate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/service"
)

var ErrRevoked = errors.New("user credentials have been revoked")

type Manager struct {
	gate     sync.RWMutex
	mu       sync.Mutex
	sessions map[*Identity]map[*Session]struct{}
	counters map[trafficKey]*TrafficCounter
}

type Identity struct {
	manager *Manager
	Name    string
	valid   bool // guarded by Manager.gate; pointer identity prevents delete/recreate ABA
}

type entry struct {
	fingerprint string
	identity    *Identity
}
type Table struct {
	manager *Manager
	users   map[string]entry
}

func NewManager() *Manager {
	return &Manager{sessions: make(map[*Identity]map[*Session]struct{}), counters: make(map[trafficKey]*TrafficCounter)}
}
func FromContext(ctx context.Context) *Manager {
	if m := service.FromContext[*Manager](ctx); m != nil {
		return m
	}
	return NewManager()
}
func (m *Manager) NewTable() *Table { return &Table{manager: m, users: make(map[string]entry)} }

// Prepare is read-only. The returned publication runs inside Manager.Commit.
// Fingerprints contain credentials and the effective policy, never array positions.
func (t *Table) Prepare(fingerprints map[string]string, force map[string]bool) (map[string]*Identity, func() []*Identity) {
	t.manager.gate.RLock()
	defer t.manager.gate.RUnlock()
	next := make(map[string]entry, len(fingerprints))
	identities := make(map[string]*Identity, len(fingerprints))
	for name, fingerprint := range fingerprints {
		old, ok := t.users[name]
		if !ok || old.fingerprint != fingerprint || force[name] {
			old = entry{fingerprint: fingerprint, identity: &Identity{Name: name, manager: t.manager}}
		}
		next[name] = old
		identities[name] = old.identity
	}
	var retired []*Identity
	for name, old := range t.users {
		if next[name].identity != old.identity {
			retired = append(retired, old.identity)
		}
	}
	return identities, func() []*Identity {
		for _, identity := range retired {
			identity.valid = false
		}
		for _, entry := range next {
			entry.identity.valid = true
		}
		t.users = next
		return retired
	}
}

// Commit gates only publication/admission, never network I/O. Close sockets after
// releasing the gate so callbacks can unregister without deadlocking the writer.
func (m *Manager) Commit(publish func() []*Identity) int {
	m.gate.Lock()
	retired := publish()
	m.mu.Lock()
	var sessions []*Session
	for _, identity := range retired {
		for session := range m.sessions[identity] {
			sessions = append(sessions, session)
		}
	}
	m.mu.Unlock()
	m.gate.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
	return len(sessions)
}

// Close terminates this inbound's current authenticated sessions on shutdown.
func (t *Table) Close() error {
	t.manager.Commit(func() []*Identity {
		var retired []*Identity
		for _, e := range t.users {
			e.identity.valid = false
			retired = append(retired, e.identity)
		}
		t.users = make(map[string]entry)
		return retired
	})
	return nil
}

type sessionKey struct{}
type Session struct {
	net.Conn
	closeTransport net.Conn
	cancel         context.CancelFunc
	manager        *Manager
	identity       *Identity // guarded by manager.mu
	closed         bool
	extra          []io.Closer
}

func (m *Manager) NewSession(ctx context.Context, conn net.Conn, transport ...net.Conn) (context.Context, *Session) {
	ctx, cancel := context.WithCancel(ctx)
	s := &Session{Conn: conn, manager: m, cancel: cancel}
	if len(transport) > 0 {
		s.closeTransport = transport[0]
	}
	return context.WithValue(ctx, sessionKey{}, s), s
}
func (s *Session) Upstream() any           { return s.Conn }
func (s *Session) ReaderReplaceable() bool { return true }
func (s *Session) WriterReplaceable() bool { return true }

func Bind(ctx context.Context, identity *Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, _ := ctx.Value(sessionKey{}).(*Session)
	if s == nil || identity == nil {
		return ErrRevoked
	}
	m := s.manager
	m.gate.RLock()
	defer m.gate.RUnlock()
	if identity.manager != m || !identity.valid {
		return ErrRevoked
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.closed || (s.identity != nil && s.identity != identity) {
		return ErrRevoked
	}
	if s.identity == nil {
		s.identity = identity
		if m.sessions[identity] == nil {
			m.sessions[identity] = make(map[*Session]struct{})
		}
		m.sessions[identity][s] = struct{}{}
	}
	return nil
}

func Attach(ctx context.Context, closer io.Closer) error {
	s, _ := ctx.Value(sessionKey{}).(*Session)
	if s == nil {
		_ = closer.Close()
		return ErrRevoked
	}
	s.manager.mu.Lock()
	if s.closed {
		s.manager.mu.Unlock()
		_ = closer.Close()
		return ErrRevoked
	}
	s.extra = append(s.extra, closer)
	s.manager.mu.Unlock()
	return nil
}
func (s *Session) Close() error {
	s.manager.mu.Lock()
	if s.closed {
		s.manager.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.identity != nil {
		delete(s.manager.sessions[s.identity], s)
		if len(s.manager.sessions[s.identity]) == 0 {
			delete(s.manager.sessions, s.identity)
		}
	}
	extra := s.extra
	s.extra = nil
	s.manager.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	// Close the per-session transport before TLS close_notify, so a stalled
	// peer cannot block revocation. Never unwrap an HTTP/2 transport to its shared TCP socket.
	if s.closeTransport != nil {
		_ = s.closeTransport.Close()
	}
	err := s.Conn.Close()
	for _, closer := range extra {
		_ = closer.Close()
	}
	return err
}

func Key(name string, index int) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("\x00anonymous:%d", index)
}
func Fingerprint(value any) string {
	data, _ := json.Marshal(value)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func (m *Manager) SessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, sessions := range m.sessions {
		count += len(sessions)
	}
	return count
}
