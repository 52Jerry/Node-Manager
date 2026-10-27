"""VLESS-only bounded publication. Feature is opt-in; legacy WG remains owned by baseline.

This file and rolling_runtime.py are deployed together. Publication never sends
HUP to a VLESS generation; only the original shared instance uses its legacy
reload, after VLESS has been moved to a ready private listener.
"""

from __future__ import annotations
import copy, hashlib, json, os, pathlib, re, socket, subprocess, sys, time, uuid

try:
    import fcntl
except ImportError:
    fcntl = None
import rolling_runtime as rr

PREFIX = "niusu-vless-gen-"
NAT = "NIUSU_VLESS_ACTIVE"
GUARD = "NIUSU_VLESS_GUARD"
TAG = "niusu-vless-publication"


def command(args, timeout=15, input=None):
    p = subprocess.run(
        args, input=input, capture_output=True, text=True, timeout=timeout
    )
    if p.returncode:
        raise rr.RolloutError("command_failed:" + args[0])
    return p.stdout


def canonical(spec):
    return json.loads(pathlib.Path(spec["canonicalPath"]).read_text())


def projection(config, tag):
    value = copy.deepcopy(config)
    inbound = next(
        (
            i
            for i in value["inbounds"]
            if i.get("tag") == tag and i.get("type") == "vless"
        ),
        None,
    )
    if inbound is None or inbound.get("listen_port") != 20168:
        raise rr.RolloutError("vless_20168_required")
    if inbound.get("multiplex", {}).get("enabled") is True or inbound.get("transport"):
        raise rr.RolloutError("only_nonmultiplexed_tcp_vless_supported")
    identifiers = set()
    auth_names = set()
    for user in inbound.get("users", []):
        try:
            identifier = str(uuid.UUID(user["uuid"]))
        except (KeyError, ValueError, TypeError, AttributeError):
            raise rr.RolloutError("invalid_vless_uuid") from None
        if (
            identifier in identifiers
            or not user.get("name")
            or user["name"] in auth_names
        ):
            raise rr.RolloutError("duplicate_or_missing_vless_identity")
        identifiers.add(identifier)
        auth_names.add(user["name"])
    value["inbounds"] = [inbound]
    names = {u.get("name") for u in inbound.get("users", [])}
    rules = []
    for rule in value.get("route", {}).get("rules", []):
        constrained = rule.get("inbound", [])
        if isinstance(constrained, str):
            constrained = [constrained]
        if constrained and tag not in constrained:
            continue
        auth = rule.get("auth_user", [])
        if isinstance(auth, str):
            auth = [auth]
        if auth and not names.intersection(auth):
            continue
        rules.append(rule)
    value["route"]["rules"] = rules
    wanted = {r.get("outbound") for r in rules if r.get("outbound")}
    wanted.add(value["route"].get("final"))
    by_tag = {o.get("tag"): o for o in value.get("outbounds", [])}
    for name in list(wanted):
        if name in by_tag and by_tag[name].get("detour"):
            wanted.add(by_tag[name]["detour"])
    value["outbounds"] = [
        o for o in value.get("outbounds", []) if o.get("tag") in wanted
    ]
    if set(value.get("experimental", {})) != {"clash_api"}:
        raise rr.RolloutError("unsupported_extra_runtime_listener")
    # Controller coordinates logging and Clash endpoint separately.
    value["experimental"]["clash_api"]["external_controller"] = "127.0.0.1:9090"
    return value


def state_path(spec):
    return pathlib.Path(spec["statePath"])


def write_state(spec, state):
    rr.atomic_json(state_path(spec), state)


def load_state(spec, telemetry=False):
    value = json.loads(state_path(spec).read_text())
    if value.get("bootId") != rr.boot_id():
        raise rr.RolloutError("vless_publication_bootstrap_required")
    if value.get("phase") != "steady":
        raise rr.RolloutError("vless_publication_recovery_required")
    return value


def configured_spec():
    path = os.environ.get("NODE_MANAGER_VLESS_PUBLICATION_SPEC")
    if not path:
        return None
    spec = json.loads(pathlib.Path(path).read_text())
    if spec.get("enabled") is not True:
        return None
    return spec


def snapshot():
    spec = configured_spec()
    if spec is None:
        return None
    state = load_state(spec, True)
    for endpoint in state.get("generations", []):
        if process_identity(endpoint["pid"])["startTicks"] != endpoint["startTicks"]:
            raise rr.RolloutError("vless_generation_restarted_review_required")
    return rr.merged_connections(state)


def proxies():
    spec = configured_spec()
    state = load_state(spec, True)
    base = rr.api(state["baseline"], "/proxies")
    active = next(
        (g for g in state.get("generations", []) if g["id"] == state["activeId"]), None
    )
    if active:
        latest = rr.api(active, "/proxies")
        base["proxies"].update(latest["proxies"])
    return base


def close(connection_id):
    return rr.close_connection(load_state(configured_spec(), True), connection_id)


def process_identity(pid):
    raw = pathlib.Path("/proc", str(pid), "stat").read_text()
    return {"pid": int(pid), "startTicks": int(raw.rsplit(")", 1)[1].split()[19])}


def unit_identity(unit):
    if not re.fullmatch(PREFIX + r"[0-9a-f]{12}\.service", unit):
        raise rr.RolloutError("unowned_unit")
    pid = int(command(["systemctl", "show", unit, "-p", "MainPID", "--value"]).strip())
    return process_identity(pid) if pid else {"pid": 0, "startTicks": 0}


def has_live_sockets(endpoint):
    if process_identity(endpoint["pid"])["startTicks"] != endpoint["startTicks"]:
        raise rr.RolloutError("process_identity_changed")
    root = pathlib.Path("/proc", str(endpoint["pid"]))
    owned = set()
    for f in (root / "fd").iterdir():
        try:
            link = os.readlink(f)
        except OSError:
            continue
        if link.startswith("socket:["):
            owned.add(link[8:-1])
    for name in ["tcp", "tcp6", "udp", "udp6"]:
        for line in (root / "net" / name).read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 9 and fields[9] in owned:
                if name.startswith("udp") or fields[3] not in {"0A", "07"}:
                    return True
    return False


def collect_empty(spec, state):
    for gen in list(state.get("generations", [])):
        if gen["id"] == state["activeId"]:
            continue
        if has_live_sockets(gen):
            continue
        one = rr.api(gen, "/connections")
        if one.get("connections") != []:
            continue
        time.sleep(0.1)
        if has_live_sockets(gen):
            continue
        two = rr.api(gen, "/connections")
        if two.get("connections") != []:
            continue
        pending = copy.deepcopy(state)
        pending["phase"] = "retiring"
        pending["retiringEndpoint"] = gen
        pending["retiringDelta"] = {}
        pending["generations"] = [
            g for g in pending["generations"] if g["id"] != gen["id"]
        ]
        for key in ["uploadTotal", "downloadTotal"]:
            value = two.get(key)
            initial = gen.get("nativeStart", {}).get(key, 0)
            if type(value) is not int or value < initial:
                raise rr.RolloutError("retirement_counter_unknown")
            pending.setdefault("retiredTotals", {}).setdefault(key, 0)
            pending["retiredTotals"][key] += value - initial
            pending["retiringDelta"][key] = value - initial
        write_state(spec, pending)
        stop_generation(gen)
        pending.pop("retiringEndpoint")
        pending.pop("retiringDelta")
        pending["phase"] = "steady"
        write_state(spec, pending)
        state = pending
    return state


def force_retire_one_for_capacity(spec, state):
    """Retire one superseded generation when an explicitly enabled policy needs room.

    Existing sessions on that generation are disconnected and may reconnect to
    the active generation. The active route and process are never stopped.
    """
    active = next(
        (g for g in state["generations"] if g["id"] == state["activeId"]), None
    )
    if active is None or current_target_port() != active["port"]:
        raise rr.RolloutError("active_route_changed_before_forced_retirement")
    if unit_identity(active["unit"]) != {
        "pid": active["pid"], "startTicks": active["startTicks"]
    }:
        raise rr.RolloutError("active_generation_changed_before_forced_retirement")
    old = next(
        (g for g in state["generations"] if g["id"] != state["activeId"]), None
    )
    if old is None:
        return None
    if unit_identity(old["unit"]) != {
        "pid": old["pid"], "startTicks": old["startTicks"]
    }:
        raise rr.RolloutError("generation_identity_changed")
    snap = rr.api(old, "/connections")
    if not isinstance(snap.get("connections"), list):
        raise rr.RolloutError("retirement_snapshot_unknown")
    delta = {}
    for key in ("uploadTotal", "downloadTotal"):
        value = snap.get(key)
        initial = old.get("nativeStart", {}).get(key, 0)
        if type(value) is not int or value < initial:
            raise rr.RolloutError("retirement_counter_unknown")
        delta[key] = value - initial
    pending = copy.deepcopy(state)
    pending["phase"] = "retiring"
    pending["retiringEndpoint"] = old
    pending["retiringDelta"] = delta
    pending["generations"] = [
        g for g in pending["generations"] if g["id"] != old["id"]
    ]
    for key, value in delta.items():
        pending.setdefault("retiredTotals", {}).setdefault(key, 0)
        pending["retiredTotals"][key] += value
    write_state(spec, pending)
    command(["systemctl", "stop", old["unit"]], timeout=25)
    if unit_identity(old["unit"])["pid"] != 0:
        raise rr.RolloutError("forced_retirement_unit_still_running")
    pending.pop("retiringEndpoint")
    pending.pop("retiringDelta")
    pending["phase"] = "steady"
    write_state(spec, pending)
    return pending


def stop_generation(gen):
    observed = unit_identity(gen["unit"])
    if observed != {"pid": gen["pid"], "startTicks": gen["startTicks"]}:
        raise rr.RolloutError("generation_identity_changed")
    if has_live_sockets(gen):
        raise rr.RolloutError("generation_still_has_sessions")
    command(["systemctl", "stop", gen["unit"]], timeout=15)


def listener_inode(port):
    text = command(["ss", "-Hlntpe", "sport = :%d" % port])
    found = re.search(r"ino:(\d+)", text)
    return found.group(1) if found else None


def bootstrap(spec):
    value = canonical(spec)
    view = projection(value, spec["vlessTag"])
    if state_path(spec).exists():
        old = json.loads(state_path(spec).read_text())
        if old.get("bootId") == rr.boot_id():
            return load_state(spec)
    # Boot-only restoration must precede the manager. Old generation services
    # are intentionally not enabled independently, so stale slots don't boot.
    detach(spec, False)
    base = {
        "id": "baseline",
        "apiPort": spec["baselineApiPort"],
        "apiSecret": value["experimental"]["clash_api"].get("secret", ""),
        "nativeStart": {"uploadTotal": 0, "downloadTotal": 0},
        "nativeCarry": {"uploadTotal": 0, "downloadTotal": 0},
    }
    rr.api(base, "/connections")
    credits = spec.get("initialLegacyReloadCredits", 0)
    if type(credits) is not int or credits not in [0, 1]:
        raise rr.RolloutError("invalid_legacy_reload_allowance")
    state = {
        "version": 1,
        "bootId": rr.boot_id(),
        "phase": "steady",
        "baseline": base,
        "generations": [],
        "retiredTotals": {"uploadTotal": 0, "downloadTotal": 0},
        "activeId": "baseline",
        "activeHash": rr.digest(view),
        "baselineHash": rr.digest(value),
        "userFingerprints": rr.user_fingerprints(view, {spec["vlessTag"]}),
        "legacyVlessDrained": False,
        "legacyReloadCredits": credits,
    }
    write_state(spec, state)
    return state


def jump(chain, hook):
    args = [
        "-p",
        "tcp",
        "--syn",
        "--dport",
        "20168",
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-m",
        "comment",
        "--comment",
        TAG,
        "-j",
        chain,
    ]
    if hook == "PREROUTING":
        return ["-m", "addrtype", "--dst-type", "LOCAL"] + args
    return ["-o", "lo"] + args


def ensure_guard(spec):
    base = ["iptables", "-w", "5"]
    ports = [str(s["port"]) for s in spec["slots"]]
    # Guard the private generation ports before attaching any redirect.
    text = rr.guard_restore(
        [{"publicPort": 20168, "candidatePort": s["port"]} for s in spec["slots"]]
    ).replace("NIUSU_SB_GUARD", GUARD)
    command(["iptables-restore", "-w", "5", "--noflush"], input=text)
    def guard_rule(group):
        return [
            "-p", "tcp", "-m", "multiport", "--dports", ",".join(group),
            "-m", "comment", "--comment", TAG, "-j", GUARD,
        ]

    # xt_multiport accepts at most 15 destination ports per rule. Install the
    # expanded rules before removing the original eight-port rule, so existing
    # private listeners stay guarded throughout a capacity expansion.
    groups = [ports[index:index + 15] for index in range(0, len(ports), 15)]
    for group in groups:
        guard = guard_rule(group)
        if subprocess.run(
            base + ["-t", "filter", "-C", "INPUT"] + guard, capture_output=True
        ).returncode:
            command(base + ["-t", "filter", "-I", "INPUT", "1"] + guard)
    if len(groups) > 1:
        old_guard = guard_rule(ports[:8])
        if subprocess.run(
            base + ["-t", "filter", "-C", "INPUT"] + old_guard,
            capture_output=True,
        ).returncode == 0:
            command(base + ["-t", "filter", "-D", "INPUT"] + old_guard)


def ensure_routes(spec):
    ensure_guard(spec)
    base = ["iptables", "-w", "5"]
    if subprocess.run(base + ["-t", "nat", "-S", NAT], capture_output=True).returncode:
        command(base + ["-t", "nat", "-N", NAT])
    for hook in ["PREROUTING", "OUTPUT"]:
        if subprocess.run(
            base + ["-t", "nat", "-C", hook] + jump(NAT, hook), capture_output=True
        ).returncode:
            command(base + ["-t", "nat", "-I", hook, "1"] + jump(NAT, hook))


def switch_port(port):
    # Empty chain returns to the baseline listener; never flush conntrack.
    mappings = [] if port is None else [{"publicPort": 20168, "candidatePort": port}]
    text = rr.routing_restore(mappings).replace("NIUSU_SB_ACTIVE", NAT)
    command(["iptables-restore", "-w", "5", "--noflush"], input=text)


def detach(spec, verify_baseline=True):
    if verify_baseline:
        state = load_state(spec)
        if rr.digest(canonical(spec)) != state["baselineHash"]:
            raise rr.RolloutError("baseline_not_current_for_new_connection_rollback")
    base = ["iptables", "-w", "5", "-t", "nat"]
    for hook in ["PREROUTING", "OUTPUT"]:
        while (
            subprocess.run(
                base + ["-C", hook] + jump(NAT, hook), capture_output=True
            ).returncode
            == 0
        ):
            command(base + ["-D", hook] + jump(NAT, hook))
    # Guard remains in place; removing it could expose retained generations.
    if verify_baseline:
        state["activeId"] = "baseline"
        state["legacyVlessDrained"] = False
        state["activeHash"] = rr.digest(projection(canonical(spec), spec["vlessTag"]))
        write_state(spec, state)


def available_bytes():
    return (
        int(
            next(
                l.split()[1]
                for l in pathlib.Path("/proc/meminfo").read_text().splitlines()
                if l.startswith("MemAvailable:")
            )
        )
        * 1024
    )


def validate_spec(spec):
    for key in [
        "canonicalPath",
        "statePath",
        "lockPath",
        "generationDirectory",
        "binary",
        "probePython",
        "probeCommand",
    ]:
        if not isinstance(spec.get(key), str) or not re.fullmatch(
            r"/[A-Za-z0-9_./-]+", spec[key]
        ):
            raise rr.RolloutError("invalid_spec_path")
    slots = spec.get("slots", [])
    if not 1 <= len(slots) <= rr.MAX_GENERATIONS:
        raise rr.RolloutError("invalid_slot_limit")
    ports = [p for slot in slots for p in [slot["port"], slot["apiPort"]]]
    if len(set(ports)) != len(ports) or any(
        type(p) is not int
        or not 1024 <= p <= 65535
        or p in [20168, 20169, 5001, 41235, 9090]
        for p in ports
    ):
        raise rr.RolloutError("unsafe_slot_ports")
    if len({s["name"] for s in slots}) != len(slots):
        raise rr.RolloutError("duplicate_slots")
    namespace = spec.get("networkNamespacePath")
    if namespace:
        if not re.fullmatch(r"/run/netns/niusu-vless-test-[0-9a-f]+", namespace):
            raise rr.RolloutError("unowned_test_namespace")
        if (
            os.stat("/proc/self/ns/net").st_ino != os.stat(namespace).st_ino
            or os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino
        ):
            raise rr.RolloutError("test_must_run_inside_isolated_namespace")
        if not re.fullmatch(
            r"niusu-vless-test-[0-9a-f]+\.service", spec.get("baselineUnit", "")
        ):
            raise rr.RolloutError("unowned_test_baseline_unit")
    elif spec.get("baselineUnit", "sing-box") != "sing-box":
        raise rr.RolloutError("unexpected_production_baseline")


def stage(spec, state, value):
    slot = rr.choose_slot(
        state,
        spec["slots"],
        available_bytes(),
        spec["reserveBytes"],
        spec["candidateBudgetBytes"],
    )
    ident = uuid.uuid4().hex[:12]
    unit = PREFIX + ident + ".service"
    directory = pathlib.Path(spec["generationDirectory"]) / ident
    directory.mkdir(parents=True, mode=0o700)
    target = directory / "config.json"
    view = projection(value, spec["vlessTag"])
    mapping = {
        "tag": spec["vlessTag"],
        "publicPort": 20168,
        "candidatePort": slot["port"],
    }
    candidate = rr.build_candidate(view, [mapping], slot["apiPort"])
    health = "niusu-internal-publication:" + uuid.uuid4().hex
    probe_user = {
        "name": health,
        "uuid": str(uuid.uuid4()),
        "flow": next(
            (
                u.get("flow", "")
                for u in candidate["inbounds"][0]["users"]
                if u.get("flow")
            ),
            "",
        ),
    }
    candidate["inbounds"][0]["users"].append(probe_user)
    if any(o.get("tag") == "niusu-publication-health" for o in candidate["outbounds"]):
        raise rr.RolloutError("reserved_probe_outbound_exists")
    candidate["outbounds"].append({"type": "direct", "tag": "niusu-publication-health"})
    candidate["route"]["rules"] = [
        {
            "auth_user": [health],
            "ip_cidr": ["127.0.0.1/32"],
            "port": [61499],
            "outbound": "niusu-publication-health",
        },
        {"auth_user": [health], "action": "reject"},
    ] + candidate["route"]["rules"]
    rr.atomic_json(target, candidate)
    command([spec["binary"], "check", "-c", str(target)], timeout=12)
    unit_path = pathlib.Path("/etc/systemd/system") / unit
    if unit_path.exists():
        raise rr.RolloutError("generation_unit_collision")
    namespace = (
        ("NetworkNamespacePath=" + spec["networkNamespacePath"] + "\n")
        if spec.get("networkNamespacePath")
        else ""
    )
    expiry = "RuntimeMaxSec=600\n" if spec.get("networkNamespacePath") else ""
    unit_path.write_text(
        "[Unit]\nDescription=NiuSu isolated VLESS generation "
        + ident
        + "\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=simple\n"
        + namespace
        + expiry
        + "ExecStart="
        + spec["binary"]
        + " run -c "
        + str(target)
        + "\nRestart=on-failure\nRestartSec=3\nMemoryMax="
        + str(spec["generationMemoryMaxBytes"])
        + "\nTasksMax=8192\nLimitNOFILE=262144\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n"
    )
    try:
        ensure_guard(spec)
        command(["systemctl", "daemon-reload"])
        command(["systemctl", "start", unit], timeout=12)
        endpoint = {
            "id": ident,
            "unit": unit,
            "slot": slot["name"],
            "port": slot["port"],
            "apiPort": slot["apiPort"],
            "apiSecret": value["experimental"]["clash_api"].get("secret", ""),
            "hash": rr.digest(view),
            "configPath": str(target),
            "configHash": rr.digest(candidate),
            **unit_identity(unit),
        }
        return verify_candidate(spec, endpoint, candidate, view, target)
    except Exception:
        # It has never been published. Only our probe can hold a connection.
        subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=15)
        unit_path.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        if directory.exists() and not any(directory.iterdir()):
            directory.rmdir()
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=15)
        raise


def verify_candidate(spec, endpoint, candidate, view, target):
    port = endpoint["port"]
    deadline = time.monotonic() + 10
    while True:
        try:
            rr.readiness(endpoint, [port], {o["tag"] for o in view["outbounds"]})
            break
        except (OSError, rr.RolloutError):
            if time.monotonic() > deadline:
                raise
            time.sleep(0.1)
    # The external probe must run real Reality/Vision and reject invalid auth.
    proof_args = [spec["probePython"], spec["probeCommand"], str(target)]
    if spec.get("networkNamespacePath"):
        proof_args.append("--allow-plain-isolated-test")
    proof = command(proof_args, timeout=12)
    checked = json.loads(proof)
    if checked.get("passed") is not True or checked.get("configHash") != rr.digest(
        candidate
    ):
        raise rr.RolloutError("vless_protocol_probe_failed")
    if (
        not spec.get("networkNamespacePath")
        and checked.get("realityVision") is not True
    ):
        raise rr.RolloutError("production_reality_probe_required")
    if (
        hashlib.sha256(target.read_bytes()).hexdigest()
        != hashlib.sha256(
            json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    ):
        # atomic_json has no trailing newline; exact immutable file identity.
        raise rr.RolloutError("candidate_file_changed")
    current = rr.api(endpoint, "/connections")
    if current.get("connections") != []:
        raise rr.RolloutError("probe_sessions_not_drained")
    endpoint["nativeStart"] = {k: current[k] for k in ["uploadTotal", "downloadTotal"]}
    return endpoint


def enforce_changed(state, old_names, new_names):
    changed = rr.changed_names(old_names, new_names)
    if changed:
        for item in rr.merged_connections(state)["connections"]:
            if rr.matching_connection(item, changed):
                rr.close_connection(state, item["id"])


def current_target_port():
    p = subprocess.run(
        ["iptables", "-w", "5", "-t", "nat", "-S", NAT],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if p.returncode:
        return None
    rules = [l for l in p.stdout.splitlines() if l.startswith("-A ")]
    if not rules:
        return None
    if len(rules) != 1:
        raise rr.RolloutError("owned_nat_chain_drift")
    match = re.fullmatch(
        r"-A "
        + NAT
        + r" -p tcp(?: -m tcp)? --dport 20168 -j REDIRECT --to-ports (\d+)",
        rules[0],
    )
    if not match:
        raise rr.RolloutError("owned_nat_chain_drift")
    return int(match.group(1))


def collect_orphans(spec, state):
    referenced = {g["unit"] for g in state.get("generations", [])}
    for field in ["pendingEndpoint", "retiringEndpoint"]:
        if field in state:
            referenced.add(state[field]["unit"])
    base = pathlib.Path(spec["generationDirectory"]).resolve()
    for path in pathlib.Path("/etc/systemd/system").glob(PREFIX + "*.service"):
        if path.name in referenced or not re.fullmatch(
            PREFIX + r"[0-9a-f]{12}\.service", path.name
        ):
            continue
        ident = path.name[len(PREFIX) : -len(".service")]
        target = base / ident / "config.json"
        if (
            "ExecStart=" + spec["binary"] + " run -c " + str(target) + "\n"
            not in path.read_text()
        ):
            continue
        observed = unit_identity(path.name)
        if observed["pid"]:
            # No journal ever published this unit, but late unexpected sockets still protect it.
            endpoint = {**observed, "unit": path.name}
            if has_live_sockets(endpoint):
                raise rr.RolloutError(
                    "unreferenced_candidate_has_sockets_review_required"
                )
            command(["systemctl", "stop", path.name])
        path.unlink()
        target.unlink(missing_ok=True)
        if target.parent.exists() and not any(target.parent.iterdir()):
            target.parent.rmdir()


def recover(spec):
    state = json.loads(state_path(spec).read_text())
    if state.get("bootId") != rr.boot_id():
        return bootstrap(spec)
    phase = state.get("phase")
    if phase == "steady":
        return state
    if phase == "retiring":
        endpoint = state["retiringEndpoint"]
        status = command(
            ["systemctl", "show", endpoint["unit"], "-p", "ActiveState", "--value"]
        ).strip()
        if status == "active":
            # Abort retirement if a late socket exists. Never kill that socket.
            if has_live_sockets(endpoint):
                state["generations"].append(endpoint)
                for key, value in state["retiringDelta"].items():
                    state["retiredTotals"][key] -= value
            else:
                stop_generation(endpoint)
        elif status not in {"inactive", "failed"}:
            raise rr.RolloutError("retirement_unit_state_unknown")
        state.pop("retiringEndpoint")
        state.pop("retiringDelta")
        state["phase"] = "steady"
        write_state(spec, state)
        return state
    if phase == "switching":
        pending = state["pendingEndpoint"]
        old = next(
            (g for g in state["generations"] if g["id"] == state["activeId"]), None
        )
        actual = current_target_port()
        wanted = rr.digest(projection(canonical(spec), spec["vlessTag"]))
        if actual not in {pending["port"], old["port"] if old else None}:
            raise rr.RolloutError("unexpected_live_nat_target")
        if unit_identity(pending["unit"]) != {
            "pid": pending["pid"],
            "startTicks": pending["startTicks"],
        }:
            raise rr.RolloutError("pending_generation_changed")
        if (
            rr.digest(json.loads(pathlib.Path(pending["configPath"]).read_text()))
            != pending["configHash"]
        ):
            raise rr.RolloutError("pending_config_changed")
        prior_names = state["userFingerprints"]
        if wanted == pending["hash"]:
            rr.readiness(pending, [pending["port"]], set())
            ensure_routes(spec)
            switch_port(pending["port"])
            state["activeId"] = pending["id"]
            state["activeHash"] = pending["hash"]
            state["userFingerprints"] = state["pendingFingerprints"]
        elif wanted == state["activeHash"]:
            # The caller restored the canonical files. Roll back only NEW flows;
            # keep the pending instance in telemetry until any sessions drain.
            ensure_routes(spec)
            switch_port(old["port"] if old else None)
            prior_names = state["pendingFingerprints"]
        else:
            raise rr.RolloutError("third_revision_requires_manual_recovery")
        if all(g["id"] != pending["id"] for g in state["generations"]):
            state["generations"].append(pending)
        state.pop("pendingEndpoint")
        state.pop("pendingFingerprints")
        state["phase"] = "steady"
        write_state(spec, state)
        enforce_changed(state, prior_names, state["userFingerprints"])
        return state
    if phase == "baseline_reloading":
        # Never guess an epoch and accidentally count the previous core twice.
        # A changed listener plus the still-current intended canonical file is
        # the recoverable case. Other cases stay blocked for explicit repair.
        inode = listener_inode(spec["baselineApiPort"])
        if not inode or inode == state["previousBaselineListener"]:
            raise rr.RolloutError("baseline_reload_epoch_ambiguous")
        # The listener has already advanced to a new accounting epoch. A newer
        # canonical revision may arrive during that reload; finish this epoch
        # and let the next apply publish the newer revision.
        rr.readiness(state["baseline"], [20169, 5001], set())
        state["baselineHash"] = state.pop("baselinePendingHash")
        state.pop("previousBaselineListener")
        state["legacyVlessDrained"] = spec.get("routingEnabled", True) is True
        state["phase"] = "steady"
        write_state(spec, state)
        return state
    raise rr.RolloutError("unknown_publication_phase")


def reload_baseline(spec, state, value):
    if rr.digest(value) == state["baselineHash"]:
        return state
    guarded = spec.get("routingEnabled", True) is True
    consume_credit = False
    if guarded and not state.get("legacyVlessDrained", False):
        rows = command(["ss", "-Htan", "sport = :20168"]).splitlines()
        busy = any(
            row.split()[0] not in {"LISTEN", "TIME-WAIT", "CLOSE", "CLOSED"}
            for row in rows
            if row.split()
        )
        if busy:
            if state.get("legacyReloadCredits", 0) < 1:
                raise rr.CapacityError(
                    "legacy_vless_flows_still_draining_no_hup_allowed"
                )
            consume_credit = True
        else:
            state = {**state, "legacyVlessDrained": True}
    before = rr.api(state["baseline"], "/connections")
    inode = listener_inode(spec["baselineApiPort"])
    if not inode:
        raise rr.RolloutError("baseline_listener_unknown")
    pending = copy.deepcopy(state)
    pending["phase"] = "baseline_reloading"
    pending["baselinePendingHash"] = rr.digest(value)
    if consume_credit:
        pending["legacyReloadCredits"] -= 1
    pending["previousBaselineListener"] = inode
    pending["baseline"]["apiSecret"] = value["experimental"]["clash_api"].get(
        "secret", ""
    )
    for key in ["uploadTotal", "downloadTotal"]:
        pending["baseline"].setdefault("nativeCarry", {}).setdefault(key, 0)
        pending["baseline"]["nativeCarry"][key] += before[key]
    write_state(spec, pending)
    command(["systemctl", "reload", spec.get("baselineUnit", "sing-box")], timeout=12)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        changed = listener_inode(spec["baselineApiPort"])
        if changed and changed != inode:
            try:
                rr.readiness(pending["baseline"], [20169, 5001], set())
                # Concurrent canonical updates must not strand the journal in
                # baseline_reloading after the new listener is ready. The next
                # apply compares baselineHash and reloads the newer revision.
                pending["baselineHash"] = pending.pop("baselinePendingHash")
                pending.pop("previousBaselineListener", None)
                pending["legacyVlessDrained"] = guarded
                pending["phase"] = "steady"
                write_state(spec, pending)
                return pending
            except (OSError, rr.RolloutError):
                pass
        time.sleep(0.1)
    raise rr.RolloutError("baseline_new_instance_not_ready")


def publish(spec, activate=False):
    if spec.get("enabled") is not True:
        raise rr.RolloutError("publication_not_authorized")
    state = load_state(spec)
    value = canonical(spec)
    view = projection(value, spec["vlessTag"])
    wanted = rr.digest(view)
    if spec.get("routingEnabled", True) is not True:
        # Keep aggregation alive for draining generations during rollback.
        state = reload_baseline(spec, state, value)
        new_names = rr.user_fingerprints(view, {spec["vlessTag"]})
        enforce_changed(state, state["userFingerprints"], new_names)
        state["userFingerprints"] = new_names
        state["activeHash"] = wanted
        write_state(spec, state)
        return {
            "activeId": state["activeId"],
            "routingEnabled": False,
            "generationCount": len(state["generations"]),
        }
    if state["activeId"] == "baseline" or wanted != state["activeHash"]:
        state = collect_empty(spec, state)
        reusable = next((g for g in state["generations"] if g["hash"] == wanted), None)
        if reusable is not None:
            endpoint = reusable
        else:
            while True:
                try:
                    endpoint = stage(spec, state, value)
                    break
                except rr.CapacityError as exc:
                    if (
                        spec.get("forceRetireOldOnCapacity") is not True
                        or str(exc) not in {
                            "insufficient_memory_keep_existing_instances",
                            "draining_slots_busy_keep_existing_connections",
                        }
                    ):
                        raise
                    updated = force_retire_one_for_capacity(spec, state)
                    if updated is None:
                        raise
                    state = updated
        old_names = state["userFingerprints"]
        new_names = rr.user_fingerprints(view, {spec["vlessTag"]})
        intent = copy.deepcopy(state)
        intent["phase"] = "switching"
        intent["pendingEndpoint"] = endpoint
        intent["pendingFingerprints"] = new_names
        write_state(spec, intent)
        ensure_routes(spec)
        switch_port(endpoint["port"])
        if reusable is None:
            state["generations"].append(endpoint)
        state["activeId"] = endpoint["id"]
        state["activeHash"] = wanted
        state["userFingerprints"] = new_names
        state["phase"] = "steady"
        write_state(spec, state)
        enforce_changed(state, old_names, new_names)
    if not activate:
        state = reload_baseline(spec, state, value)
    return {
        "activeId": state["activeId"],
        "activeHash": state["activeHash"],
        "generationCount": len(state["generations"]),
        "baselineProtected": True,
    }


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument(
        "action",
        choices=[
            "bootstrap",
            "activate",
            "apply",
            "status",
            "detach",
            "recover",
            "boot",
            "collect",
        ],
    )
    args = parser.parse_args()
    spec = json.loads(pathlib.Path(args.spec).read_text())
    if fcntl is None:
        raise rr.RolloutError("linux_flock_required")
    validate_spec(spec)
    pathlib.Path(spec["lockPath"]).parent.mkdir(parents=True, exist_ok=True)
    with open(spec["lockPath"], "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == "boot":
            if state_path(spec).exists() and json.loads(state_path(spec).read_text()).get("bootId") == rr.boot_id():
                recover(spec)
            else:
                bootstrap(spec)
            result = publish(spec, activate=True)
        elif args.action == "collect":
            s = recover(spec)
            collect_orphans(spec, s)
            s = collect_empty(spec, s)
            result = {"phase": s["phase"], "generationCount": len(s["generations"])}
        elif args.action == "bootstrap":
            s = bootstrap(spec)
            result = {"phase": s["phase"], "activeId": s["activeId"]}
        elif args.action in ["activate", "apply"]:
            s = recover(spec)
            collect_orphans(spec, s)
            result = publish(spec, args.action == "activate")
        elif args.action == "recover":
            s = recover(spec)
            result = {"phase": s["phase"], "activeId": s["activeId"]}
        elif args.action == "detach":
            detach(spec)
            result = {
                "newConnectionsReturnToBaseline": True,
                "retainedProcessesNotStopped": True,
            }
        else:
            s = load_state(spec)
            result = {
                "phase": s["phase"],
                "activeId": s["activeId"],
                "generationCount": len(s["generations"]),
            }
    print(json.dumps({"ok": True, **result}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never emit config contents or credentials from subprocess errors.
        reason = str(exc) if isinstance(exc, rr.RolloutError) else type(exc).__name__
        try:
            rr.atomic_json(
                pathlib.Path("/var/lib/node-manager/vless-publication-last-error.json"),
                {"reason": reason, "time": time.time()},
            )
        except OSError:
            pass
        print(
            json.dumps(
                {
                    "ok": False,
                    "reason": reason,
                }
            )
        )
        raise SystemExit(1)
