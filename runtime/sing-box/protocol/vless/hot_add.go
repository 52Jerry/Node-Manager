package vless

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/userstate"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
)

type vlessIdentity struct {
	Name  string
	Index int
	Token *userstate.Identity
}

func (h *Inbound) PrepareUserUpdate(raw any, changed map[string]bool) (func() []*userstate.Identity, error) {
	options, ok := raw.(*option.VLESSInboundOptions)
	if !ok {
		return nil, fmt.Errorf("invalid VLESS user options")
	}
	return h.prepareUsers(options, changed)
}

func (h *Inbound) prepareUsers(options *option.VLESSInboundOptions, changed map[string]bool) (func() []*userstate.Identity, error) {
	fingerprints := make(map[string]string, len(options.Users))
	for index, user := range options.Users {
		if h.kernelTLS && user.Flow != "" {
			return nil, fmt.Errorf("VLESS flow changes are incompatible with kernel TLS")
		}
		if user.Flow != "" && user.Flow != "xtls-rprx-vision" {
			return nil, fmt.Errorf("invalid VLESS flow")
		}
		key := userstate.Key(user.Name, index)
		if _, exists := fingerprints[key]; exists {
			return nil, fmt.Errorf("duplicate VLESS user")
		}
		fingerprints[key] = userstate.Fingerprint(user)
	}
	tokens, publish := h.userTable.Prepare(fingerprints, changed)
	identities := make([]vlessIdentity, len(options.Users))
	ids := make([]string, len(options.Users))
	flows := make([]string, len(options.Users))
	for index, user := range options.Users {
		identities[index] = vlessIdentity{Name: user.Name, Index: index, Token: tokens[userstate.Key(user.Name, index)]}
		ids[index] = user.UUID
		flows[index] = user.Flow
	}
	prepared := vless.NewService[vlessIdentity](h.logger, adapter.NewUpstreamContextHandlerEx(h.newConnectionEx, h.newPacketConnectionEx))
	prepared.OnAuthenticated = func(ctx context.Context, id vlessIdentity) error { return userstate.Bind(ctx, id.Token) }
	prepared.UpdateUsers(identities, ids, flows)
	return func() []*userstate.Identity { retired := publish(); h.service.Store(prepared); return retired }, nil
}
