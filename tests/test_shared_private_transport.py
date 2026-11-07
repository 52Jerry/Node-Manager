from copy import deepcopy
from pathlib import Path
import json
import subprocess
from unittest.mock import patch

import pytest

from shared_manager.transport import PrivateTransport, migrate_listeners, restore_listeners
from shared_manager.firewall import install, transport_rules
from shared_manager.deploy import prepare


def core():
    return {
        "inbounds": [
            {"type": kind, "tag": kind, "listen": "10.44.0.1", "listen_port": port,
             "users": [{"name": "customer-1", "uuid": "unchanged-identity", "password": "unchanged-auth"}],
             "tls": {"reality": {"private_key": "unchanged-key"}}}
            for kind, port in (("vless", 6666), ("vmess", 7777), ("socks", 9999))
        ],
        "outbounds": [{"type": "socks", "tag": "res-1", "server": "8.8.8.8", "server_port": 1080,
                       "username": "upstream-user", "password": "upstream-password"}],
        "route": {"rules": [{"auth_user": ["customer-1"], "outbound": "res-1"}]},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9091", "secret": "unchanged-api-auth"}},
    }


def test_migration_preserves_every_field_except_shared_listener_addresses():
    original = core()
    before = deepcopy(original)
    migrated = migrate_listeners(original, PrivateTransport())
    assert original == before
    for row in migrated["inbounds"]:
        assert row["listen"] == "172.16.208.118"
        row["listen"] = "10.44.0.1"
    assert migrated == original


def test_migration_is_idempotent_and_never_recreates_identities():
    once = migrate_listeners(core(), PrivateTransport())
    assert migrate_listeners(once, PrivateTransport()) == once


def test_rollback_uses_fresh_config_and_retains_users_created_after_cutover():
    current = migrate_listeners(core(), PrivateTransport())
    for inbound in current["inbounds"]:
        inbound["users"].append({"name": "new-purchase", "uuid": "new-identity"})
    current["outbounds"][0]["password"] = "updated-after-cutover"
    restored = restore_listeners(current, PrivateTransport())
    assert all(x["listen"] == "10.44.0.1" and len(x["users"]) == 2 for x in restored["inbounds"])
    assert restored["outbounds"] == current["outbounds"]
    for inbound in restored["inbounds"]:
        inbound["listen"] = "172.16.208.118"
    assert restored == current


@pytest.mark.parametrize("mutation", ["wrong-port", "duplicate", "missing", "public-listener", "unknown-overlay"])
def test_unexpected_or_partial_instances_are_refused(mutation):
    data = core()
    if mutation == "wrong-port": data["inbounds"][0]["listen_port"] = 20168
    elif mutation == "duplicate": data["inbounds"].append(deepcopy(data["inbounds"][0]))
    elif mutation == "missing": data["inbounds"].pop()
    elif mutation == "public-listener": data["inbounds"][0]["listen"] = "0.0.0.0"
    else: data["inbounds"].append({"type": "http", "listen": "10.44.0.1", "listen_port": 18080})
    with pytest.raises(ValueError): migrate_listeners(data, PrivateTransport())


@pytest.mark.parametrize("values", [
    {"exit_private": "8.8.8.8"}, {"entry_private": "127.0.0.1"},
    {"exit_private": "0.0.0.0"}, {"entry_private": "172.16.208.118"},
    {"interface": "ens19; reboot"}, {"exit_private": "example.com"},
])
def test_bad_addresses_and_interfaces_are_rejected(values):
    with pytest.raises(ValueError): PrivateTransport(**values)


def test_private_forwarding_uses_physical_interface_and_preserves_protocol_ports():
    rules = transport_rules("entry", PrivateTransport())
    flat = " ".join(" ".join(args) for _, _, args in rules)
    assert "10.44." not in flat and "wg1" not in flat
    assert "172.16.208.118" in flat and "172.16.80.15" in flat and "ens19" in flat
    assert all("6666,7777,9999" in args for _, _, args in rules)
    assert all(port not in flat.split() for port in ("20168", "20169", "5001", "22"))


def test_exit_restricts_shared_ports_to_entry_or_local_health_checks():
    rules = transport_rules("exit", PrivateTransport())
    accepts = [args for _, _, args in rules if args[-1] == "ACCEPT"]
    assert len(accepts) == 2
    assert any("172.16.80.15/32" in args and "ens19" in args for args in accepts)
    assert any("lo" in args for args in accepts)
    assert rules[-1][2][-1] == "DROP"


def test_install_does_not_flush_rules_or_switch_entry_before_return_rules_exist():
    calls = []
    def invoke(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1 if "-C" in args else 0)
    with patch("shared_manager.firewall.subprocess.run", side_effect=invoke): install("entry")
    inserts = [args for args in calls if "-I" in args]
    assert inserts[-1][inserts[-1].index("-I") + 1] == "PREROUTING"
    assert all(flag not in args for args in calls for flag in ("-F", "-X", "-P"))
    assert all("-w" in args for args in calls)


def test_new_installation_defaults_to_private_listeners_without_overwriting_existing(tmp_path):
    source = tmp_path / "source"
    for name in ("node-manager", "shared_manager"):
        (source / name).mkdir(parents=True)
        (source / name / "example.py").write_text("# fixture\n")
    binary = tmp_path / "sing-box"
    binary.write_bytes(b"fixture-only")
    destination = tmp_path / "instance"
    prepare(source, destination, binary, "panel.example", "proxy.example")
    data = json.loads((destination / "config/sing-box.json").read_text())
    assert {x["listen"] for x in data["inbounds"]} == {"172.16.208.118"}
    assert {x["listen_port"] for x in data["inbounds"]} == {6666, 7777, 9999}
    before = (destination / "config/sing-box.json").read_bytes()
    with pytest.raises(ValueError): prepare(source, destination, binary, "panel.example", "proxy.example")
    assert (destination / "config/sing-box.json").read_bytes() == before
