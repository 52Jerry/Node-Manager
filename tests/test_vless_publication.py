import copy, json, sys
from pathlib import Path
from unittest import mock
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
import rolling_runtime as rr
import vless_publication as vp


def config():
    return {
        "log": {"level": "warn"},
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": "test-only",
            }
        },
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-reality",
                "listen": "0.0.0.0",
                "listen_port": 20168,
                "users": [
                    {
                        "name": "node-manager:a",
                        "uuid": "00000000-0000-4000-8000-000000000001",
                        "flow": "xtls-rprx-vision",
                    }
                ],
                "tls": {
                    "enabled": True,
                    "reality": {"private_key": "unchanged-fixture"},
                },
            },
            {"type": "vmess", "tag": "vmess", "listen_port": 20169, "users": []},
            {"type": "tproxy", "tag": "wg-pilot", "listen_port": 41235},
        ],
        "route": {
            "rules": [
                {
                    "inbound": ["wg-pilot"],
                    "source_ip_cidr": ["10.77.0.2/32"],
                    "outbound": "wg-out",
                },
                {"auth_user": ["node-manager:a"], "outbound": "node-manager-out:a"},
            ],
            "final": "direct",
        },
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {
                "type": "socks",
                "tag": "node-manager-out:a",
                "server": "192.0.2.1",
                "server_port": 1080,
            },
            {
                "type": "socks",
                "tag": "wg-out",
                "server": "192.0.2.2",
                "server_port": 1080,
            },
        ],
    }


def endpoint(name, port=9090):
    return {"id": name, "apiPort": port}


def snapshot(upload=20, download=30, ids=()):
    return {
        "uploadTotal": upload,
        "downloadTotal": download,
        "connections": [
            {
                "id": i,
                "upload": 2,
                "download": 3,
                "metadata": {"sourceIP": "192.0.2.5"},
                "chains": ["node-manager-out:a"],
            }
            for i in ids
        ],
    }


def state():
    return {
        "phase": "steady",
        "baseline": endpoint("baseline"),
        "generations": [dict(endpoint("abcdef123456", 62090), slot="a")],
        "activeId": "abcdef123456",
        "retiredTotals": {"uploadTotal": 10, "downloadTotal": 15},
    }


def test_projection_keeps_reality_and_all_vless_auth():
    c = config()
    p = vp.projection(c, "vless-reality")
    assert p["inbounds"] == [c["inbounds"][0]]
    assert p["route"]["rules"] == [c["route"]["rules"][1]]
    assert "wg-out" not in {x["tag"] for x in p["outbounds"]}
    assert c == config()


def test_wg_only_update_does_not_roll_vless():
    a = config()
    b = copy.deepcopy(a)
    b["inbounds"][-1]["listen_port"] = 41236
    b["outbounds"][-1]["server"] = "192.0.2.9"
    assert vp.projection(a, "vless-reality") == vp.projection(b, "vless-reality")


def test_vmess_only_identity_does_not_roll_vless():
    a = config()
    b = copy.deepcopy(a)
    b["inbounds"][1]["users"] = [{"name": "only-vmess", "uuid": "test"}]
    b["route"]["rules"].append({"auth_user": ["only-vmess"], "outbound": "wg-out"})
    assert vp.projection(a, "vless-reality") == vp.projection(b, "vless-reality")


def test_added_vless_identity_changes_target():
    a = config()
    b = copy.deepcopy(a)
    b["inbounds"][0]["users"].append(
        {"name": "node-manager:b", "uuid": "00000000-0000-4000-8000-000000000002"}
    )
    assert rr.digest(vp.projection(a, "vless-reality")) != rr.digest(
        vp.projection(b, "vless-reality")
    )


def test_candidate_preserves_uuid_tls_and_routes():
    c = vp.projection(config(), "vless-reality")
    v = rr.build_candidate(
        c,
        [{"tag": "vless-reality", "publicPort": 20168, "candidatePort": 62000}],
        62090,
        True,
    )
    assert v["inbounds"][0]["users"] == c["inbounds"][0]["users"]
    assert v["inbounds"][0]["tls"] == c["inbounds"][0]["tls"]
    assert v["route"] == c["route"]
    assert v["inbounds"][0]["listen"] == "127.0.0.1"
    assert v["experimental"]["clash_api"]["external_controller"] == "127.0.0.1:62090"
    assert c["inbounds"][0]["listen_port"] == 20168


def test_candidate_refuses_unexpected_public_port():
    with pytest.raises(rr.RolloutError):
        rr.build_candidate(
            config(),
            [{"tag": "vless-reality", "publicPort": 443, "candidatePort": 62000}],
            62090,
        )


def test_uuid_aliases_are_rejected_before_publication():
    c = config()
    c["inbounds"][0]["users"][0]["uuid"] = "not-a-uuid"
    with pytest.raises(rr.RolloutError, match="invalid_vless_uuid"):
        vp.projection(c, "vless-reality")


def test_duplicate_authentication_identity_is_rejected():
    c = config()
    c["inbounds"][0]["users"].append(copy.deepcopy(c["inbounds"][0]["users"][0]))
    with pytest.raises(rr.RolloutError, match="duplicate"):
        vp.projection(c, "vless-reality")


def test_existing_connection_ids_and_counters_stay_stable():
    s = state()
    values = {
        "baseline": snapshot(ids=["old"]),
        "abcdef123456": snapshot(5, 8, ["new"]),
    }
    merged = rr.merged_connections(s, lambda e, p: values[e["id"]])
    assert [x["id"] for x in merged["connections"]] == ["old", "rr:abcdef123456:new"]
    assert merged["uploadTotal"] == 35
    assert merged["downloadTotal"] == 53
    assert values["abcdef123456"]["connections"][0]["id"] == "new"


def test_counters_subtract_probe_and_carry_original_instance_history():
    s = state()
    s["baseline"]["nativeCarry"] = {"uploadTotal": 100, "downloadTotal": 200}
    s["generations"][0]["nativeStart"] = {"uploadTotal": 2, "downloadTotal": 4}
    m = rr.merged_connections(s, lambda e, p: snapshot(5, 8))
    assert m["uploadTotal"] == 118
    assert m["downloadTotal"] == 227


@pytest.mark.parametrize("bad", [True, -1, "20", 2**64])
def test_invalid_native_counters_do_not_silently_become_zero(bad):
    s = state()
    with pytest.raises(rr.RolloutError):
        rr.merged_connections(s, lambda e, p: {**snapshot(), "uploadTotal": bad})


def test_counter_reset_requires_review():
    s = state()
    s["generations"][0]["nativeStart"] = {"uploadTotal": 99, "downloadTotal": 0}
    with pytest.raises(rr.RolloutError):
        rr.merged_connections(s, lambda e, p: snapshot())


def test_missing_draining_instance_fails_instead_of_undercounting():
    def fetch(e, p):
        if e["id"] == "baseline":
            raise rr.RolloutError("unavailable")
        return snapshot()

    with pytest.raises(rr.RolloutError):
        rr.merged_connections(state(), fetch)


def test_close_routes_to_original_instance_without_closing_everyone():
    calls = []
    s = state()
    rr.close_connection(s, "old", lambda *a: calls.append(a))
    rr.close_connection(s, "rr:abcdef123456:new", lambda *a: calls.append(a))
    assert [(x[0]["id"], x[1], x[2]) for x in calls] == [
        ("baseline", "/connections/old", "DELETE"),
        ("abcdef123456", "/connections/new", "DELETE"),
    ]


def test_stale_generation_id_is_not_redirected_to_other_users():
    with pytest.raises(rr.RolloutError):
        rr.close_connection(
            state(), "rr:unknown:one", lambda *a: pytest.fail("must not send delete")
        )


def test_memory_pressure_does_not_reclaim_live_generations():
    with pytest.raises(rr.CapacityError):
        rr.choose_slot(state(), [{"name": "b"}], 100, 80, 30)


def test_full_slots_apply_backpressure():
    with pytest.raises(rr.CapacityError):
        rr.choose_slot(state(), [{"name": "a"}], 1000, 100, 100)


def test_usable_free_slot_is_selected():
    assert (
        rr.choose_slot(state(), [{"name": "a"}, {"name": "b"}], 1000, 100, 100)["name"]
        == "b"
    )


def test_socket_check_prevents_killing_idle_mux_even_when_api_empty():
    s = state()
    s["generations"].append(
        dict(endpoint("draining", 62091), slot="b", pid=10, startTicks=20)
    )
    with mock.patch.object(
        vp, "has_live_sockets", return_value=True
    ), mock.patch.object(
        vp.rr, "api", return_value=snapshot(ids=[])
    ), mock.patch.object(
        vp, "stop_generation"
    ) as stop:
        assert vp.collect_empty({}, s) == s
        stop.assert_not_called()


def test_auth_changes_only_close_affected_user():
    c = config()
    old = rr.user_fingerprints(c, {"vless-reality"})
    c["route"]["rules"].insert(0, {"auth_user": ["node-manager:a"], "action": "reject"})
    new = rr.user_fingerprints(c, {"vless-reality"})
    affected = rr.changed_names(old, new)
    assert affected == {"node-manager:a"}
    assert rr.matching_connection({"chains": ["node-manager-out:a"]}, affected)
    assert not rr.matching_connection({"chains": ["node-manager-out:b"]}, affected)


def test_unmodified_users_are_not_disconnected_for_a_new_user():
    c = config()
    old = rr.user_fingerprints(c, {"vless-reality"})
    c["inbounds"][0]["users"].append({"name": "node-manager:b", "uuid": "new"})
    new = rr.user_fingerprints(c, {"vless-reality"})
    assert rr.changed_names(old, new) == set()


def test_no_implicit_production_activation():
    with pytest.raises(rr.RolloutError, match="not_authorized"):
        vp.publish({"enabled": False})


def test_atomic_switch_commands_are_scoped_to_owned_chain():
    with mock.patch.object(vp, "command") as run:
        vp.switch_port(62000)
    args = run.call_args.args[0]
    text = run.call_args.kwargs["input"]
    assert args[0] == "iptables-restore" and "--noflush" in args
    assert "-F NIUSU_VLESS_ACTIVE" in text
    assert "-F PREROUTING" not in text
    assert "--to-ports 62000" in text


def test_activation_keeps_original_shared_instance_running():
    c = config()
    p = vp.projection(c, "vless-reality")
    s = {
        "phase": "steady",
        "baseline": endpoint("baseline"),
        "generations": [],
        "activeId": "baseline",
        "activeHash": rr.digest(p),
        "baselineHash": rr.digest(c),
        "userFingerprints": rr.user_fingerprints(p, {"vless-reality"}),
    }
    gen = {"id": "abcdef123456", "slot": "a", "port": 62000, "hash": rr.digest(p)}
    with mock.patch.object(vp, "load_state", return_value=s), mock.patch.object(
        vp, "canonical", return_value=c
    ), mock.patch.object(
        vp, "collect_empty", side_effect=lambda spec, st: st
    ), mock.patch.object(
        vp, "stage", return_value=gen
    ), mock.patch.object(
        vp, "write_state"
    ), mock.patch.object(
        vp, "ensure_routes"
    ), mock.patch.object(
        vp, "switch_port"
    ) as switch, mock.patch.object(
        vp, "reload_baseline"
    ) as reload:
        r = vp.publish({"enabled": True, "vlessTag": "vless-reality"}, True)
        assert r["activeId"] == gen["id"]
        switch.assert_called_once_with(62000)
        reload.assert_not_called()


def test_identical_config_does_not_rotate_or_reload():
    c = config()
    p = vp.projection(c, "vless-reality")
    s = {
        "phase": "steady",
        "baseline": endpoint("baseline"),
        "generations": [],
        "activeId": "already-isolated",
        "activeHash": rr.digest(p),
        "baselineHash": rr.digest(c),
        "userFingerprints": rr.user_fingerprints(p, {"vless-reality"}),
    }
    with mock.patch.object(vp, "load_state", return_value=s), mock.patch.object(
        vp, "canonical", return_value=c
    ), mock.patch.object(vp, "stage") as stage, mock.patch.object(vp, "command") as cmd:
        vp.publish({"enabled": True, "vlessTag": "vless-reality"})
        stage.assert_not_called()
        cmd.assert_not_called()


def test_existing_noop_reload_does_not_require_protocol_failures():
    c = config()
    s = {"baselineHash": rr.digest(c)}
    with mock.patch.object(vp, "command") as command:
        assert vp.reload_baseline({}, s, c) == s
        command.assert_not_called()


def test_recover_completed_baseline_reload_after_canonical_advances():
    older = config()
    newer = copy.deepcopy(older)
    newer["inbounds"][1]["users"] = [{"name": "new-vmess", "uuid": "new"}]
    s = {
        "bootId": "boot",
        "phase": "baseline_reloading",
        "baseline": endpoint("baseline"),
        "baselinePendingHash": rr.digest(older),
        "previousBaselineListener": "old-inode",
        "generations": [],
        "activeId": "baseline",
    }
    with mock.patch.object(
        vp, "state_path", return_value=mock.Mock(read_text=lambda: json.dumps(s))
    ), mock.patch.object(vp.rr, "boot_id", return_value="boot"), mock.patch.object(
        vp, "listener_inode", return_value="new-inode"
    ), mock.patch.object(vp.rr, "readiness") as ready, mock.patch.object(
        vp, "canonical", return_value=newer
    ), mock.patch.object(vp, "write_state") as write:
        recovered = vp.recover({"baselineApiPort": 9090, "routingEnabled": True})
    assert recovered["phase"] == "steady"
    assert recovered["baselineHash"] == rr.digest(older)
    assert recovered["baselineHash"] != rr.digest(newer)
    ready.assert_called_once()
    write.assert_called_once()


def test_reload_completes_when_canonical_advances_during_hup():
    older = config()
    newer = copy.deepcopy(older)
    newer["inbounds"][1]["users"] = [{"name": "new-vmess", "uuid": "new"}]
    s = {
        "phase": "steady",
        "baseline": endpoint("baseline"),
        "baselineHash": "previous-revision",
        "legacyVlessDrained": True,
    }
    with mock.patch.object(vp.rr, "api", return_value=snapshot()), mock.patch.object(
        vp, "listener_inode", side_effect=["old-inode", "new-inode"]
    ), mock.patch.object(vp, "command"), mock.patch.object(
        vp.rr, "readiness"
    ), mock.patch.object(vp, "canonical", return_value=newer), mock.patch.object(
        vp, "write_state"
    ) as write:
        result = vp.reload_baseline({"baselineApiPort": 9090}, s, older)
    assert result["phase"] == "steady"
    assert result["baselineHash"] == rr.digest(older)
    assert result["baselineHash"] != rr.digest(newer)
    assert write.call_count == 2


def test_forced_capacity_retirement_preserves_active_and_counters():
    active = {"id": "active", "unit": "active-unit", "pid": 11, "startTicks": 21, "port": 62000}
    old = {"id": "old", "unit": "old-unit", "pid": 12, "startTicks": 22,
           "port": 62010, "nativeStart": {"uploadTotal": 5, "downloadTotal": 7}}
    s = {"phase": "steady", "activeId": "active", "generations": [old, active],
         "retiredTotals": {"uploadTotal": 10, "downloadTotal": 20}}

    def identity(unit):
        if unit == "active-unit":
            return {"pid": 11, "startTicks": 21}
        if stopped:
            return {"pid": 0, "startTicks": 0}
        return {"pid": 12, "startTicks": 22}

    stopped = []
    writes = []
    with mock.patch.object(vp, "current_target_port", return_value=62000), mock.patch.object(
        vp, "unit_identity", side_effect=identity
    ), mock.patch.object(vp.rr, "api", return_value=snapshot(20, 30, ["connected"])), mock.patch.object(
        vp, "command", side_effect=lambda args, **kwargs: stopped.append(args[2])
    ), mock.patch.object(vp, "write_state", side_effect=lambda spec, value: writes.append(copy.deepcopy(value))):
        result = vp.force_retire_one_for_capacity({}, s)

    assert stopped == ["old-unit"]
    assert result["phase"] == "steady" and result["generations"] == [active]
    assert result["retiredTotals"] == {"uploadTotal": 25, "downloadTotal": 43}
    assert [value["phase"] for value in writes] == ["retiring", "steady"]


def test_capacity_retirement_requires_explicit_policy():
    c = config()
    s = {"phase": "steady", "activeId": "active", "activeHash": "old-hash",
         "generations": [{"id": "active", "hash": "old-hash"}], "userFingerprints": {}}
    with mock.patch.object(vp, "load_state", return_value=s), mock.patch.object(
        vp, "canonical", return_value=c
    ), mock.patch.object(vp, "collect_empty", side_effect=lambda spec, state: state), mock.patch.object(
        vp, "stage", side_effect=rr.CapacityError("insufficient_memory_keep_existing_instances")
    ), mock.patch.object(vp, "force_retire_one_for_capacity") as force:
        with pytest.raises(rr.CapacityError):
            vp.publish({"enabled": True, "vlessTag": "vless-reality"}, activate=True)
    force.assert_not_called()


def test_capacity_policy_retires_old_then_retries_stage():
    c = config()
    active = {"id": "active", "hash": "old-hash"}
    old = {"id": "old", "hash": "older-hash"}
    s = {"phase": "steady", "activeId": "active", "activeHash": "old-hash",
         "generations": [old, active], "userFingerprints": {}}
    freed = {**s, "generations": [active]}
    candidate = {"id": "new", "hash": rr.digest(vp.projection(c, "vless-reality")),
                 "port": 62020}
    with mock.patch.object(vp, "load_state", return_value=s), mock.patch.object(
        vp, "canonical", return_value=c
    ), mock.patch.object(vp, "collect_empty", side_effect=lambda spec, state: state), mock.patch.object(
        vp, "stage", side_effect=[rr.CapacityError("insufficient_memory_keep_existing_instances"), candidate]
    ) as stage, mock.patch.object(
        vp, "force_retire_one_for_capacity", return_value=freed
    ) as force, mock.patch.object(vp, "ensure_routes"), mock.patch.object(
        vp, "switch_port"
    ), mock.patch.object(vp, "write_state"), mock.patch.object(vp, "enforce_changed"):
        result = vp.publish({"enabled": True, "vlessTag": "vless-reality",
                             "forceRetireOldOnCapacity": True}, activate=True)
    assert result["activeId"] == "new"
    assert stage.call_count == 2
    force.assert_called_once_with(mock.ANY, s)


def test_legacy_connections_without_explicit_allowance_prevent_shared_hup():
    c = config()
    s = {"baselineHash": "older", "legacyVlessDrained": False, "legacyReloadCredits": 0}
    with mock.patch.object(
        vp, "command", return_value="ESTAB 0 0 127.0.0.1:20168 127.0.0.1:30000\n"
    ) as cmd:
        with pytest.raises(rr.CapacityError, match="no_hup"):
            vp.reload_baseline({}, s, c)
        assert cmd.call_count == 1 and cmd.call_args.args[0][0] == "ss"


def test_switch_recovery_retains_pending_instance_when_caller_rolled_back():
    c = config()
    p = vp.projection(c, "vless-reality")
    fingerprints = rr.user_fingerprints(p, {"vless-reality"})
    old = {"id": "old", "port": 62000}
    pending = {
        "id": "new",
        "port": 62010,
        "pid": 2,
        "startTicks": 3,
        "unit": "unit",
        "configPath": "not-opened",
        "configHash": rr.digest({}),
        "hash": "new-revision",
    }
    s = {
        "bootId": "boot",
        "phase": "switching",
        "baseline": endpoint("baseline"),
        "generations": [old],
        "activeId": "old",
        "activeHash": rr.digest(p),
        "userFingerprints": fingerprints,
        "pendingEndpoint": pending,
        "pendingFingerprints": {**fingerprints, "node-manager:new": "new"},
    }
    with mock.patch.object(
        vp, "state_path", return_value=mock.Mock(read_text=lambda: json.dumps(s))
    ), mock.patch.object(vp.rr, "boot_id", return_value="boot"), mock.patch.object(
        vp, "canonical", return_value=c
    ), mock.patch.object(
        vp, "current_target_port", return_value=62010
    ), mock.patch.object(
        vp, "unit_identity", return_value={"pid": 2, "startTicks": 3}
    ), mock.patch.object(
        vp.pathlib.Path, "read_text", return_value="{}"
    ), mock.patch.object(
        vp, "ensure_routes"
    ), mock.patch.object(
        vp, "switch_port"
    ) as switch, mock.patch.object(
        vp, "write_state"
    ), mock.patch.object(
        vp, "enforce_changed"
    ):
        recovered = vp.recover({"vlessTag": "vless-reality"})
        assert recovered["activeId"] == "old"
        assert {g["id"] for g in recovered["generations"]} == {"old", "new"}
        switch.assert_called_once_with(62000)


def test_slot_port_validation_rejects_live_business_ports():
    spec = {
        "canonicalPath": "/tmp/c",
        "statePath": "/tmp/s",
        "lockPath": "/tmp/l",
        "generationDirectory": "/tmp/g",
        "binary": "/usr/bin/sing-box",
        "probePython": "/usr/bin/python3",
        "probeCommand": "/tmp/p",
        "slots": [{"name": "slot", "port": 20168, "apiPort": 62090}],
    }
    with pytest.raises(rr.RolloutError, match="unsafe_slot_ports"):
        vp.validate_spec(spec)


def test_slot_capacity_accepts_guarded_expansion_up_to_32():
    spec = {
        "canonicalPath": "/tmp/c",
        "statePath": "/tmp/s",
        "lockPath": "/tmp/l",
        "generationDirectory": "/tmp/g",
        "binary": "/usr/bin/sing-box",
        "probePython": "/usr/bin/python3",
        "probeCommand": "/tmp/p",
        "slots": [
            {"name": f"s{i}", "port": 63000 + 10 * i, "apiPort": 64000 + 10 * i}
            for i in range(32)
        ],
    }
    vp.validate_spec(spec)
    spec["slots"].append({"name": "s32", "port": 63320, "apiPort": 64320})
    with pytest.raises(rr.RolloutError, match="invalid_slot_limit"):
        vp.validate_spec(spec)


def test_connection_journal_accepts_expanded_generations():
    state = {
        "baseline": {"id": "baseline"},
        "generations": [{"id": str(i)} for i in range(32)],
    }
    assert len(rr.endpoints(state)) == 33
    state["generations"].append({"id": "32"})
    with pytest.raises(rr.RolloutError, match="invalid_generation_journal"):
        rr.endpoints(state)


def test_guard_expansion_chunks_multiport_before_removing_old_rule():
    slots = [
        {"name": f"s{i}", "port": 63000 + 10 * i, "apiPort": 64000 + 10 * i}
        for i in range(32)
    ]
    old_ports = ",".join(str(slot["port"]) for slot in slots[:8])

    def existing_rule(args, **_kwargs):
        value = args[args.index("--dports") + 1]
        return mock.Mock(returncode=0 if value == old_ports else 1)

    with mock.patch.object(vp.rr, "guard_restore", return_value="guard"), mock.patch.object(
        vp.subprocess, "run", side_effect=existing_rule
    ), mock.patch.object(vp, "command") as command:
        vp.ensure_guard({"slots": slots})

    calls = [call.args[0] for call in command.call_args_list]
    insertions = [args for args in calls if "-I" in args]
    assert len(insertions) == 3
    assert all(len(args[args.index("--dports") + 1].split(",")) <= 15 for args in insertions)
    assert "-D" in calls[-1] and old_ports in calls[-1]


@pytest.mark.parametrize("module", ["", " -m tcp"])
def test_recovery_reads_actual_owned_nat_rule(module):
    output = (
        "-N NIUSU_VLESS_ACTIVE\n-A NIUSU_VLESS_ACTIVE -p tcp"
        + module
        + " --dport 20168 -j REDIRECT --to-ports 62200\n"
    )
    with mock.patch.object(
        vp.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=output)
    ):
        assert vp.current_target_port() == 62200


def test_recovery_refuses_changed_business_port():
    output = "-A NIUSU_VLESS_ACTIVE -p tcp -m tcp --dport 5001 -j REDIRECT --to-ports 62200\n"
    with mock.patch.object(
        vp.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=output)
    ):
        with pytest.raises(rr.RolloutError, match="owned_nat_chain_drift"):
            vp.current_target_port()


@pytest.mark.parametrize(
    "extra", [{"multiplex": {"enabled": True}}, {"transport": {"type": "ws"}}]
)
def test_unsupported_multiplex_or_transport_cannot_enable_rollout(extra):
    value = config()
    value["inbounds"][0].update(extra)
    with pytest.raises(rr.RolloutError, match="nonmultiplexed_tcp"):
        vp.projection(value, "vless-reality")
