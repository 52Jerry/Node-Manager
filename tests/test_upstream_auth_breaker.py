"""Policy CAS, mixed-core acknowledgements and recovery without access mutation."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

import upstream_auth_breaker as breaker
from upstream_auth_breaker_routes import router


SECRET = "should-never-be-returned-credential"
CIRCUIT = "opaque_circuit_id_12345678"
REQUEST = "request_123456789012345678"


@pytest.fixture
def store(tmp_path, monkeypatch):
    policy = tmp_path / "policy.json"
    directory = tmp_path / "states"
    directory.mkdir()
    monkeypatch.setenv("NIUSU_UPSTREAM_AUTH_BREAKER_CONFIG", str(policy))
    monkeypatch.setenv("NIUSU_UPSTREAM_AUTH_BREAKER_STATE_DIR", str(directory))
    monkeypatch.setattr(breaker, "_live_cores", lambda: {})
    return policy, directory


def state_file(store, *, pid=321, state="OPEN", revision=0, age=0, ticks=900, **extra):
    value = {"schemaVersion": 1, "pid": pid, "instanceId": "instance_123456789012345678",
             "processStartedAtUnix": int(time.time()) - 300, "processStartTicks": ticks,
             "observedAtUnix": time.time() - age, "policyRevision": revision, "enabled": True,
             "policyReadAtUnix": time.time(), "policyError": "", "trackedCircuits": 1,
             "circuits": [{"id": CIRCUIT, "server": "192.0.2.10", "port": 1080,
                           "state": state, "totalAuthFailures": 4, "consecutiveFailures": 3,
                           "suppressed": 100, "nextProbeAtUnix": time.time() + 300,
                           "password": SECRET, "credentialDigest": SECRET}], **extra}
    path = store[1] / f"{pid}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path, value


def live(monkeypatch, *pids):
    monkeypatch.setattr(breaker, "_live_cores", lambda: {pid: {"processStartTicks": 900} for pid in pids})


def test_default_enabled_without_writing_or_claiming_application(store):
    result = breaker.inspect()
    assert result["policy"] == {"schemaVersion": 1, "revision": 0, **breaker.DEFAULTS}
    assert result["policySource"] == "DEFAULT" and not result["configured"]
    assert result["status"] == "UNREPORTED" and not result["applicationConfirmed"]
    assert not store[0].exists()


def test_process_discovery_covers_named_native_and_excludes_config_checks(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    proc.mkdir()
    executables = {}
    for pid, executable, command in [(321, "sing-box-niusu-r4", "run"),
                                     (322, "sing-box", "run"),
                                     (323, "sing-box", "check"),
                                     (324, "unrelated-proxy", "run")]:
        directory = proc / str(pid)
        directory.mkdir()
        (directory / "cmdline").write_bytes(f"/usr/bin/{executable}\0{command}\0-c\0/test/config.json\0".encode())
        fields = ["S"] + ["0"] * 18 + ["900"]
        (directory / "stat").write_text(f"{pid} ({executable}) " + " ".join(fields))
        executables[str(directory / "exe")] = "/usr/bin/" + executable
    monkeypatch.setattr(breaker.os, "readlink", lambda path: executables[str(path)])
    assert breaker._live_cores(proc) == {321: {"processStartTicks": 900}, 322: {"processStartTicks": 900}}


def test_persist_off_and_on_with_revision_cas(store):
    off = breaker.update({**breaker.DEFAULTS, "enabled": False}, 0)
    assert off["policy"]["enabled"] is False and off["policy"]["revision"] == 1
    document = json.loads(store[0].read_text())
    assert document["probeRequests"] == []
    on = breaker.update(breaker.DEFAULTS, 1)
    assert on["policy"]["enabled"] is True and on["policy"]["revision"] == 2
    if os.name != "nt":
        assert store[0].stat().st_mode & 0o777 == 0o600


def test_concurrent_cas_only_one_writer_wins(store):
    def attempt(_):
        try:
            breaker.update(breaker.DEFAULTS, 0)
            return "OK"
        except breaker.BreakerError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=16) as executor:
        outcomes = list(executor.map(attempt, range(16)))
    assert outcomes.count("OK") == 1
    assert outcomes.count("BREAKER_POLICY_CONFLICT") == 15
    assert json.loads(store[0].read_text())["revision"] == 1


def test_configured_reader_group_survives_every_atomic_replace(store, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv("NIUSU_UPSTREAM_AUTH_BREAKER_READER_GROUP", "niusu-breaker")
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=456)))
    ownership, modes = [], []
    monkeypatch.setattr(breaker.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid)), raising=False)
    monkeypatch.setattr(breaker.os, "fchmod", lambda fd, mode: modes.append(mode), raising=False)
    breaker.update(breaker.DEFAULTS, 0)
    breaker.update({**breaker.DEFAULTS, "enabled": False}, 1)
    assert ownership == [(-1, 456), (-1, 456)]
    assert modes == [0o640, 0o640]
    assert json.loads(store[0].read_text())["revision"] == 2


def test_unknown_reader_group_preserves_previous_policy(store, monkeypatch):
    from types import SimpleNamespace
    breaker.update(breaker.DEFAULTS, 0)
    original = store[0].read_bytes()
    monkeypatch.setenv("NIUSU_UPSTREAM_AUTH_BREAKER_READER_GROUP", "missing")
    def missing_group(name):
        raise KeyError(name)
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=missing_group))
    with pytest.raises(breaker.BreakerError, match="BREAKER_READER_GROUP_UNAVAILABLE"):
        breaker.update({**breaker.DEFAULTS, "enabled": False}, 1)
    assert store[0].read_bytes() == original
    assert not list(store[0].parent.glob(".policy.json.*"))


def test_reader_group_ownership_failure_closes_descriptor_and_keeps_policy(store, monkeypatch):
    from types import SimpleNamespace
    breaker.update(breaker.DEFAULTS, 0)
    original = store[0].read_bytes()
    monkeypatch.setenv("NIUSU_UPSTREAM_AUTH_BREAKER_READER_GROUP", "niusu-breaker")
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=456)))
    descriptors = []
    def denied(fd, uid, gid):
        descriptors.append(fd)
        raise PermissionError("ownership denied")
    monkeypatch.setattr(breaker.os, "fchown", denied, raising=False)
    with pytest.raises(breaker.BreakerError, match="BREAKER_POLICY_WRITE_FAILED"):
        breaker.update({**breaker.DEFAULTS, "enabled": False}, 1)
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert store[0].read_bytes() == original
    assert not list(store[0].parent.glob(".policy.json.*"))


def test_cross_process_cas_uses_shared_lock(store):
    source = (
        "import sys;sys.path.insert(0,sys.argv[1]);import upstream_auth_breaker as b;"
        "\ntry:b.update(b.DEFAULTS,0);print('OK')"
        "\nexcept b.BreakerError as e:print(e.code)"
    )
    module_path = str(Path(breaker.__file__).parent)
    processes = [subprocess.Popen([sys.executable, "-c", source, module_path], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) for _ in range(5)]
    outputs = [process.communicate(timeout=15) for process in processes]
    assert all(process.returncode == 0 for process in processes), outputs
    outcomes = [stdout.strip() for stdout, _ in outputs]
    assert outcomes.count("OK") == 1
    assert outcomes.count("BREAKER_POLICY_CONFLICT") == 4


def test_atomic_write_failure_keeps_last_policy(store, monkeypatch):
    breaker.update(breaker.DEFAULTS, 0)
    before = store[0].read_bytes()
    monkeypatch.setattr(breaker.os, "replace", lambda *_: (_ for _ in ()).throw(OSError(SECRET)))
    with pytest.raises(breaker.BreakerError, match="BREAKER_POLICY_WRITE_FAILED"):
        breaker.update({**breaker.DEFAULTS, "enabled": False}, 1)
    assert store[0].read_bytes() == before
    assert not list(store[0].parent.glob(".policy.json.*"))


@pytest.mark.parametrize("field,value", [("enabled", "true"), ("threshold", True),
                                          ("threshold", 0), ("windowSeconds", 3601),
                                          ("cooldownSeconds", -1), ("maxCooldownSeconds", 10)])
def test_policy_validation_is_strict(store, field, value):
    with pytest.raises(breaker.BreakerError):
        breaker.update({**breaker.DEFAULTS, field: value}, 0)
    assert not store[0].exists()


def test_invalid_policy_fails_without_secret_echo(store):
    store[0].write_text('{"password":"' + SECRET + '"}', encoding="utf-8")
    with pytest.raises(breaker.BreakerError) as caught:
        breaker.inspect()
    assert str(caught.value) == "BREAKER_POLICY_INVALID"
    assert SECRET not in str(caught.value)


def test_unknown_runtime_without_report_blocks_application(store, monkeypatch):
    live(monkeypatch, 321, 322)
    state_file(store)
    result = breaker.inspect()
    assert result["status"] == "PENDING" and not result["applicationConfirmed"]
    assert "BREAKER_CORE_UNREPORTED" in result["stateErrors"]
    assert result["cores"][1] == {"pid": 322, "reported": False, "stale": True,
                                 "processAlive": True, "identityMatched": False, "circuits": []}


def test_fresh_all_cores_acknowledge_and_unknown_fields_are_redacted(store, monkeypatch):
    live(monkeypatch, 321, 322)
    state_file(store, password=SECRET, username=SECRET)
    state_file(store, pid=322)
    result = breaker.inspect()
    assert result["applicationConfirmed"] and result["status"] == "APPLIED"
    assert SECRET not in json.dumps(result)
    assert result["cores"][0]["circuits"][0]["server"] == "192.0.2.10"


def test_diagnostic_truncation_is_explicit_without_affecting_policy_ack(store, monkeypatch):
    live(monkeypatch, 321)
    state_file(store, diagnosticsTruncated=True, omittedCircuits=23, trackedCircuits=9000)
    result = breaker.inspect()
    assert result["applicationConfirmed"]
    assert result["cores"][0]["diagnosticsTruncated"] is True
    assert result["cores"][0]["omittedCircuits"] == 23
    assert result["cores"][0]["trackedCircuits"] == 9000


@pytest.mark.parametrize("age,ticks,revision,error", [(30, 900, 0, ""), (0, 901, 0, ""),
                                                     (0, 900, 1, ""), (0, 900, 0, "BREAKER_POLICY_INVALID")])
def test_stale_reused_pid_revision_or_read_error_never_claims_applied(store, monkeypatch, age, ticks, revision, error):
    live(monkeypatch, 321)
    state_file(store, age=age, ticks=ticks, revision=revision, policyError=error)
    assert not breaker.inspect()["applicationConfirmed"]


def test_dead_core_report_is_unreported(store):
    state_file(store)
    result = breaker.inspect()
    assert result["status"] == "UNREPORTED" and result["cores"][0]["stale"]


@pytest.mark.parametrize("report_offset,expected", [(1, True), (100, False)])
def test_heartbeat_written_during_slow_inspection_uses_time_after_read(store, monkeypatch, report_offset, expected):
    live(monkeypatch, 321)
    path, value = state_file(store)
    base = time.time()
    value["observedAtUnix"] = base + report_offset
    path.write_text(json.dumps(value))
    clock = [base]
    monkeypatch.setattr(breaker.time, "time", lambda: clock[0])
    read = breaker._read_json
    def delayed_read(target, limit):
        document = read(target, limit)
        if target == path:
            clock[0] += 2
        return document
    monkeypatch.setattr(breaker, "_read_json", delayed_read)
    result = breaker.inspect()
    assert result["applicationConfirmed"] is expected
    assert result["observedAtUnix"] == base + 2


def test_unsafe_state_cannot_echo_endpoint_credentials(store, monkeypatch):
    live(monkeypatch, 321)
    path, value = state_file(store)
    value["circuits"][0]["server"] = SECRET + "@192.0.2.10"
    path.write_text(json.dumps(value))
    result = breaker.inspect()
    assert result["stateErrors"] == ["BREAKER_CORE_UNREPORTED", "BREAKER_STATE_INVALID"]
    assert SECRET not in json.dumps(result)


def test_status_symlink_is_not_followed(store, monkeypatch):
    target = store[0].parent / "outside.json"
    target.write_text(json.dumps({"password": SECRET}))
    link = store[1] / "321.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("OS does not permit unprivileged symlink creation")
    live(monkeypatch, 321)
    result = breaker.inspect()
    assert "BREAKER_UNSAFE_FILE" in result["stateErrors"]
    assert SECRET not in json.dumps(result)


def test_symlink_rejection_predicate_does_not_open_file(store, monkeypatch):
    path, _ = state_file(store)
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == path or original(self))
    live(monkeypatch, 321)
    result = breaker.inspect()
    assert "BREAKER_UNSAFE_FILE" in result["stateErrors"]
    assert not result["applicationConfirmed"]


def test_manual_probe_only_requests_single_probe_and_is_idempotent(store, monkeypatch):
    live(monkeypatch, 321)
    state_file(store)
    accepted = breaker.request_probe(CIRCUIT, REQUEST)
    assert accepted["probeRequested"] and not accepted["applicationConfirmed"]
    document = json.loads(store[0].read_text())
    assert document["revision"] == 1 and document["enabled"] is True
    assert document["probeRequests"] == [{"id": CIRCUIT, "requestId": REQUEST,
                                         "requestedAtUnix": document["probeRequests"][0]["requestedAtUnix"]}]
    assert breaker.request_probe(CIRCUIT, REQUEST) == accepted
    assert json.loads(store[0].read_text())["revision"] == 1
    with pytest.raises(breaker.BreakerError, match="BREAKER_PROBE_CONFLICT"):
        breaker.request_probe("other_circuit_123456789", REQUEST)


@pytest.mark.parametrize("state,age,expected", [("CLOSED", 0, "BREAKER_CIRCUIT_NOT_OPEN"),
                                              ("HALF_OPEN", 0, "BREAKER_CIRCUIT_NOT_OPEN"),
                                              ("OPEN", 30, "BREAKER_CIRCUIT_NOT_CURRENT")])
def test_manual_probe_requires_current_open_circuit(store, monkeypatch, state, age, expected):
    live(monkeypatch, 321)
    state_file(store, state=state, age=age)
    with pytest.raises(breaker.BreakerError, match=expected):
        breaker.request_probe(CIRCUIT, REQUEST)
    assert not store[0].exists()


def test_controller_version_fence_and_idempotent_retry(store):
    first = breaker.update(breaker.DEFAULTS, 0, "website", 5)
    assert first["policy"]["controllerRevision"] == 5
    assert breaker.update(breaker.DEFAULTS, 0, "website", 5)["policy"]["revision"] == 1
    with pytest.raises(breaker.BreakerError, match="BREAKER_CONTROLLER_STALE"):
        breaker.update({**breaker.DEFAULTS, "enabled": False}, 1, "website", 4)
    with pytest.raises(breaker.BreakerError, match="BREAKER_CONTROLLER_CONFLICT"):
        breaker.update({**breaker.DEFAULTS, "enabled": False}, 1, "website", 5)
    breaker.update({**breaker.DEFAULTS, "enabled": False}, 1)
    assert json.loads(store[0].read_text())["controllerRevision"] == 5
    with pytest.raises(breaker.BreakerError, match="BREAKER_CONTROLLER_STALE"):
        breaker.update(breaker.DEFAULTS, 2, "website", 4)
    restored = breaker.update(breaker.DEFAULTS, 2, "website", 5)
    assert restored["policy"]["revision"] == 3 and restored["policy"]["enabled"] is True


@pytest.fixture
def client(store):
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as value:
        yield value


def test_api_requires_existing_token_and_does_not_write_on_read(client, store):
    assert client.get("/api/singbox/upstream-auth-breaker").status_code in (401, 403)
    response = client.get("/api/singbox/upstream-auth-breaker", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200 and response.json()["policy"]["enabled"] is True
    assert response.headers["Cache-Control"] == "no-store"
    assert not store[0].exists()


def test_api_keeps_existing_source_allowlist(client, store, monkeypatch):
    config = router.dependencies[0].dependency.__globals__["config"]
    monkeypatch.setattr(config.security, "allowed_cidrs", "192.0.2.0/24")
    response = client.put("/api/singbox/upstream-auth-breaker", headers={"Authorization": "Bearer test-token"},
                          json={"enabled": False, "expectedRevision": 0})
    assert response.status_code == 403
    assert not store[0].exists()


def test_api_put_probe_and_validation_do_not_echo_unknown_input(client, store, monkeypatch):
    headers = {"Authorization": "Bearer test-token"}
    response = client.put("/api/singbox/upstream-auth-breaker", headers=headers,
                          json={"enabled": True, "expectedRevision": 0, "password": SECRET})
    assert response.status_code == 422 and SECRET not in response.text
    response = client.put("/api/singbox/upstream-auth-breaker", headers=headers,
                          json={"enabled": "true", "expectedRevision": 0})
    assert response.status_code == 422
    response = client.put("/api/singbox/upstream-auth-breaker", headers=headers,
                          json={"enabled": True, "expectedRevision": 0})
    assert response.status_code == 200 and response.json()["policy"]["revision"] == 1
    live(monkeypatch, 321)
    state_file(store, revision=1)
    response = client.post(f"/api/singbox/upstream-auth-breaker/circuits/{CIRCUIT}/probe",
                           headers=headers, json={"requestId": REQUEST})
    assert response.status_code == 202 and response.json()["probeRequested"]
