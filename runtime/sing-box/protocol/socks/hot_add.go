package socks

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/common/userstate"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"net"
)

type userSnapshot struct {
	required      bool
	authenticator *auth.Authenticator
	identities    map[string]*userstate.Identity
}
type snapshotKey struct{}

func (h *Inbound) PrepareUserUpdate(raw any, changed map[string]bool) (func() []*userstate.Identity, error) {
	options, ok := raw.(*option.SocksInboundOptions)
	if !ok {
		return nil, fmt.Errorf("invalid SOCKS user options")
	}
	return h.prepareUsers(options, changed)
}
func (h *Inbound) prepareUsers(options *option.SocksInboundOptions, changed map[string]bool) (func() []*userstate.Identity, error) {
	fingerprints := make(map[string]string, len(options.Users))
	for _, user := range options.Users {
		if user.Username == "" || user.Password == "" || len(user.Username) > 255 || len(user.Password) > 255 {
			return nil, fmt.Errorf("SOCKS credentials require 1 to 255 bytes")
		}
		if _, exists := fingerprints[user.Username]; exists {
			return nil, fmt.Errorf("duplicate SOCKS user")
		}
		fingerprints[user.Username] = userstate.Fingerprint(user)
	}
	identities, publish := h.userTable.Prepare(fingerprints, changed)
	required := options.RequireAuth || len(options.Users) > 0
	if previous := h.users.Load(); previous != nil && previous.required {
		required = true
	}
	if changed != nil && required && len(options.Users) == 0 && !options.RequireAuth {
		return nil, fmt.Errorf("empty authenticated SOCKS requires require_auth:true for restart safety")
	}
	prepared := &userSnapshot{required: required, authenticator: auth.NewAuthenticator(options.Users), identities: identities}
	return func() []*userstate.Identity { retired := publish(); h.users.Store(prepared); return retired }, nil
}
func bindUser(ctx context.Context) error {
	snapshot, _ := ctx.Value(snapshotKey{}).(*userSnapshot)
	name, loaded := auth.UserFromContext[string](ctx)
	if snapshot == nil || !loaded {
		return userstate.ErrRevoked
	}
	return userstate.Bind(ctx, snapshot.identities[name])
}

// SOCKS UDP association authenticates before creating its UDP socket. Bind here,
// before waiting for the first datagram, so an idle association is revocable.
type userPacketListener struct{ inbound *Inbound }

func (l userPacketListener) ListenPacket(config net.ListenConfig, ctx context.Context, network, address string) (net.PacketConn, error) {
	if err := bindUser(ctx); err != nil {
		return nil, err
	}
	conn, err := l.inbound.listener.ListenPacket(config, ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err = userstate.Attach(ctx, conn); err != nil {
		return nil, err
	}
	return conn, nil
}
