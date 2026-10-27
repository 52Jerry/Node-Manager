package vmess

import (
	"fmt"
	"github.com/sagernet/sing-box/common/userstate"
	"github.com/sagernet/sing-box/option"
)

type vmessIdentity struct {
	Name  string
	Index int
	Token *userstate.Identity
}

func (h *Inbound) PrepareUserUpdate(raw any, changed map[string]bool) (func() []*userstate.Identity, error) {
	options, ok := raw.(*option.VMessInboundOptions)
	if !ok {
		return nil, fmt.Errorf("invalid VMess user options")
	}
	return h.prepareUsers(options, changed)
}

func (h *Inbound) prepareUsers(options *option.VMessInboundOptions, changed map[string]bool) (func() []*userstate.Identity, error) {
	fingerprints := make(map[string]string, len(options.Users))
	for index, user := range options.Users {
		if changed != nil && user.AlterId != 0 {
			return nil, fmt.Errorf("dynamic VMess requires AEAD users")
		}
		key := userstate.Key(user.Name, index)
		if _, exists := fingerprints[key]; exists {
			return nil, fmt.Errorf("duplicate VMess user")
		}
		fingerprints[key] = userstate.Fingerprint(user)
	}
	tokens, publish := h.userTable.Prepare(fingerprints, changed)
	identities := make([]vmessIdentity, len(options.Users))
	ids := make([]string, len(options.Users))
	alters := make([]int, len(options.Users))
	for index, user := range options.Users {
		identities[index] = vmessIdentity{Name: user.Name, Index: index, Token: tokens[userstate.Key(user.Name, index)]}
		ids[index] = user.UUID
		alters[index] = user.AlterId
	}
	commit, err := h.service.PrepareUsers(identities, ids, alters)
	if err != nil {
		return nil, err
	}
	return func() []*userstate.Identity { retired := publish(); commit(); return retired }, nil
}
