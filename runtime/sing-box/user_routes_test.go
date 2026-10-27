package box_test

import (
	"testing"
)

func TestNativeRouteTransactionClosesOnlyChangedIdentity(t *testing.T) {
	f := newRuntimeFixture(t)
	keep := mustDial(t, f, "socks", "keep", "keep-key")
	changed := mustDial(t, f, "socks", "change", "change-key")
	initial := f.instance.UserRuntimeStatus()
	route := f.config["route"].(map[string]any)
	route["rules"].([]any)[1] = map[string]any{"auth_user": []any{"change"}, "action": "reject"}
	options := fixtureOptions(t, f.ctx, f.config)
	status, err := f.instance.ReloadUserRoutes(options.Route.Rules, options.Outbounds, &initial.Revision, initial.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if status.ClosedSessions != 1 || status.InstanceID != initial.InstanceID {
		t.Fatalf("bad receipt %+v", status)
	}
	if err = exchange(keep); err != nil {
		t.Fatal("unaffected route disconnected", err)
	}
	if err = exchange(changed); err == nil {
		t.Fatal("revoked route kept its old connection")
	}
	if _, err = f.instance.ReloadUserRoutes(options.Route.Rules, options.Outbounds, &initial.Revision, initial.InstanceID); err == nil {
		t.Fatal("stale route writer accepted")
	}
	route["rules"].([]any)[1] = map[string]any{"auth_user": []any{"change"}, "action": "route", "outbound": "change-out"}
	options = fixtureOptions(t, f.ctx, f.config)
	status, err = f.instance.ReloadUserRoutes(options.Route.Rules, options.Outbounds, &status.Revision, status.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	_ = mustDial(t, f, "socks", "change", "change-key")
	if err = exchange(keep); err != nil {
		t.Fatal(err)
	}
	// Deleting a user-owned route/outbound is also a native route transaction.
	route["rules"] = route["rules"].([]any)[:1]
	f.config["outbounds"] = f.config["outbounds"].([]any)[:2]
	options = fixtureOptions(t, f.ctx, f.config)
	if _, err = f.instance.ReloadUserRoutes(options.Route.Rules, options.Outbounds, &status.Revision, status.InstanceID); err != nil {
		t.Fatal("route delete rejected", err)
	}
}
