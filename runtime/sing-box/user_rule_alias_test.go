package box

import "testing"

func TestUserUpdatePlanScopesHistoricalAliasesAndRejectsOtherProtocolOwners(t *testing.T) {
	for _, mode := range []string{"uninstalled-alias", "other-protocol-owner", "no-managed-identity"} {
		t.Run(mode, func(t *testing.T) {
			before := fixtureObject(t, appendedFixture)
			after := fixtureObject(t, appendedFixture)
			if mode == "other-protocol-owner" {
				inbound := map[string]any{"type": "trojan", "tag": "other", "users": []any{map[string]any{"name": "old-public-name", "password": "secret"}}}
				before["inbounds"] = append(rows(before, "inbounds"), inbound)
				after["inbounds"] = append(rows(after, "inbounds"), inbound)
			}
			names := []any{"new", "old-public-name"}
			if mode == "no-managed-identity" {
				names = names[1:]
			}
			rule := map[string]any{"auth_user": names, "action": "reject"}
			nested(after, "route")["rules"] = append([]any{rule}, rows(nested(after, "route"), "rules")...)
			plan, err := planUserUpdate(before, after)
			if mode != "uninstalled-alias" {
				if err == nil {
					t.Fatal("unsafe rule update accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.changedNames["old"] || !plan.changedNames["new"] {
				t.Fatal("historical alias changed another user's policy")
			}
		})
	}
}
