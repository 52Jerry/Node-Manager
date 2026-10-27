package userstate

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRevokePreservesOtherIdentityAndRejectsLateHandshake(t *testing.T) {
	m := NewManager()
	table := m.NewTable()
	ids, publish := table.Prepare(map[string]string{"keep": "a", "change": "b"}, nil)
	m.Commit(publish)
	contexts := make(map[string]context.Context)
	peers := make(map[string]net.Conn)
	for _, name := range []string{"keep", "change"} {
		server, peer := net.Pipe()
		ctx, session := m.NewSession(context.Background(), server)
		defer session.Close()
		defer peer.Close()
		contexts[name] = ctx
		peers[name] = peer
		if err := Bind(ctx, ids[name]); err != nil {
			t.Fatal(err)
		}
	}
	_, publish = table.Prepare(map[string]string{"keep": "a", "change": "rotated"}, nil)
	if closed := m.Commit(publish); closed != 1 {
		t.Fatalf("closed %d sessions", closed)
	}
	select {
	case <-contexts["change"].Done():
	default:
		t.Fatal("revocation did not cancel pending routing/dial operations")
	}
	if contexts["keep"].Err() != nil {
		t.Fatal("unaffected session context was canceled")
	}
	_ = peers["change"].SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peers["change"].Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked connection remained open")
	}
	if err := Bind(contexts["keep"], ids["keep"]); err != nil {
		t.Fatal("unchanged identity revoked", err)
	}
	server, peer := net.Pipe()
	defer peer.Close()
	late, session := m.NewSession(context.Background(), server)
	defer session.Close()
	if err := Bind(late, ids["change"]); !errors.Is(err, ErrRevoked) {
		t.Fatal("late old authentication admitted", err)
	}
}
func TestDeleteRecreateCannotResurrectOldAuthentication(t *testing.T) {
	m := NewManager()
	table := m.NewTable()
	ids, publish := table.Prepare(map[string]string{"user": "same-password"}, nil)
	m.Commit(publish)
	_, publish = table.Prepare(nil, nil)
	m.Commit(publish)
	next, publish := table.Prepare(map[string]string{"user": "same-password"}, nil)
	m.Commit(publish)
	if ids["user"] == next["user"] {
		t.Fatal("identity token reused")
	}
	server, peer := net.Pipe()
	defer peer.Close()
	ctx, session := m.NewSession(context.Background(), server)
	defer session.Close()
	if err := Bind(ctx, ids["user"]); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	if err := Bind(ctx, next["user"]); err != nil {
		t.Fatal(err)
	}
}
func TestConcurrentAdmissionAndRevocation(t *testing.T) {
	m := NewManager()
	table := m.NewTable()
	for i := 0; i < 200; i++ {
		ids, publish := table.Prepare(map[string]string{"user": "password"}, nil)
		m.Commit(publish)
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				server, peer := net.Pipe()
				defer peer.Close()
				ctx, session := m.NewSession(context.Background(), server)
				defer session.Close()
				_ = Bind(ctx, ids["user"])
			}()
		}
		_, publish = table.Prepare(nil, nil)
		m.Commit(publish)
		wg.Wait()
		m.mu.Lock()
		remaining := len(m.sessions)
		m.mu.Unlock()
		if remaining != 0 {
			t.Fatal("session registry leaked", remaining)
		}
	}
}
