package box

import (
	"testing"
)

func TestUserUpdatePlanScopesPolicyChangesToAffectedIdentities(t *testing.T) {
	before := fixtureObject(t, originalFixture)
	after := fixtureObject(t, appendedFixture)
	plan, err := planUserUpdate(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if plan.changedNames["old"] || !plan.changedNames["new"] {
		t.Fatal("new policy affected old user", plan.changedNames)
	}
	// Removing one member of a shared rule leaves the other user's policy intact.
	before = fixtureObject(t, appendedFixture)
	after = fixtureObject(t, appendedFixture)
	rules := nested(before, "route")["rules"].([]any)
	rules[0].(map[string]any)["auth_user"] = []any{"new", "old"}
	nested(before, "route")["rules"] = rules[:1]
	rules = nested(after, "route")["rules"].([]any)
	rules[0].(map[string]any)["auth_user"] = []any{"old"}
	nested(after, "route")["rules"] = rules[:1]
	plan, err = planUserUpdate(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if plan.changedNames["old"] || !plan.changedNames["new"] {
		t.Fatal("shared rule revokes unchanged member", plan.changedNames)
	}
}
func TestUserUpdatePlanRejectsSharedTopologyAndInvalidIdentities(t *testing.T) {
	tests := map[string]func(map[string]any){
		"inverted user rule":     func(o map[string]any) { rows(nested(o, "route"), "rules")[0].(map[string]any)["invert"] = true },
		"logical user rule":      func(o map[string]any) { rows(nested(o, "route"), "rules")[0].(map[string]any)["type"] = "logical" },
		"unrestricted user rule": func(o map[string]any) { delete(rows(nested(o, "route"), "rules")[0].(map[string]any), "auth_user") },
		"duplicate tag":          func(o map[string]any) { rows(o, "outbounds")[1].(map[string]any)["tag"] = "direct" },
		"duplicate name": func(o map[string]any) {
			rows(rows(o, "inbounds")[0].(map[string]any), "users")[1].(map[string]any)["name"] = "old"
		},
		"duplicate canonical UUID": func(o map[string]any) {
			rows(rows(o, "inbounds")[0].(map[string]any), "users")[1].(map[string]any)["uuid"] = "a"
		},
		"changed port":   func(o map[string]any) { rows(o, "inbounds")[0].(map[string]any)["listen_port"] = 9999 },
		"missing target": func(o map[string]any) { rows(nested(o, "route"), "rules")[0].(map[string]any)["outbound"] = "missing" },
		"changed global priority": func(o map[string]any) {
			rules := rows(nested(o, "route"), "rules")
			rules[len(rules)-1] = map[string]any{"action": "route", "outbound": "direct"}
		},
		"removed live target": func(o map[string]any) { o["outbounds"] = rows(o, "outbounds")[:1] },
		"dependent outbound":  func(o map[string]any) { rows(o, "outbounds")[1].(map[string]any)["detour"] = "direct" },
	}
	for name, modify := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := fixtureObject(t, appendedFixture)
			modify(candidate)
			if _, err := planUserUpdate(fixtureObject(t, originalFixture), candidate); err == nil {
				t.Fatal("invalid user update accepted")
			}
		})
	}
}
