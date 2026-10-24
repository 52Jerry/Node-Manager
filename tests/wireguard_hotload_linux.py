#!/usr/bin/env python3
"""Exercise live WireGuard TPROXY generation changes in an isolated namespace.

Run this only from a private network and mount namespace, for example:

    unshare --net --mount --fork python3 wireguard_hotload_linux.py \
      "$(readlink /proc/self/ns/net)" /tmp/candidate/node-manager

All listeners, files, routes, conntrack entries and firewall rules created by
this fixture live in that namespace. No public route is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


BASE_PORT = 61037
CANDIDATE_PORT = 61038
BASE_ECHO_PORT = 61937
CANDIDATE_ECHO_PORT = 61938
CLIENT_NET = "10.77.0.0/24"
GATEWAY_IP = "10.77.0.1"
CLIENT_IP = "10.77.0.2"
UNOWNED_IP = "10.77.0.3"
INACTIVE_IP = "10.77.0.4"
TARGET_IP = "203.0.113.77"
TARGET_PORT = 18080
INACTIVE_PROBE_PORT = 61939
CONNMARK_MASK = 0xFF000000
LOW_MARK = 0x00001234
BASE_COOKIE = 0x01000000
CANDIDATE_COOKIE = 0x02000000
TEST_NS = "wg-hotload-client"
SYSTEMCTL_SERVICE = "niusu-wireguard-proxy.service"


class FixtureError(RuntimeError):
    pass


def require(condition: Any, message: str) -> None:
    if not condition:
        raise FixtureError(message)


def host_namespace_inode(value: str) -> int:
    match = re.fullmatch(r"(?:net:\[)?(\d+)\]?", value.strip())
    if not match:
        raise FixtureError("host network namespace must be an inode or net:[inode]")
    return int(match.group(1))


def check_isolation(host_netns: str) -> dict[str, int]:
    own_net = os.stat("/proc/self/ns/net").st_ino
    expected_net = host_namespace_inode(host_netns)
    require(own_net != expected_net, "refusing to run in the host network namespace")
    own_mount = os.stat("/proc/self/ns/mnt").st_ino
    init_mount = os.stat("/proc/1/ns/mnt").st_ino
    require(own_mount != init_mount, "refusing to run without a private mount namespace")
    return {"selfNetworkNamespaceInode": own_net, "hostNetworkNamespaceInode": expected_net,
            "selfMountNamespaceInode": own_mount, "initMountNamespaceInode": init_mount}


def command(args: list[str], *, timeout: float = 30, input_text: str | None = None,
            check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=input_text, capture_output=True, text=True,
                            timeout=timeout, env=os.environ.copy(), check=False)
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise FixtureError(f"{Path(args[0]).name} failed ({result.returncode}): {detail[:700]}")
    return result


def output(args: list[str], *, timeout: float = 30) -> str:
    return command(args, timeout=timeout).stdout


def require_program(name: str) -> str:
    found = shutil.which(name)
    require(found is not None, f"required executable not found on PATH: {name}")
    return os.path.abspath(found)


def private_tool_wrappers(root: Path, real_iptables: str, real_restore: str) -> Path:
    """Keep iptables real while preventing xtables from loading host modules."""
    bindir = root / "bin"
    bindir.mkdir()
    wrappers = {
        "iptables": f"#!/bin/sh\nexec {real_iptables} -M /bin/false \"$@\"\n",
        "iptables-restore": f"#!/bin/sh\nexec {real_restore} -M /bin/false \"$@\"\n",
        "systemctl": (
            "#!/bin/sh\n"
            "if [ \"$1\" = is-active ] && [ \"$2\" = " + SYSTEMCTL_SERVICE + " ]; then\n"
            "  printf 'active\\n'\n"
            "  exit 0\n"
            "fi\n"
            "printf '%s\\n' \"$*\" >> \"$WG_HOTLOAD_SYSTEMCTL_GUARD_LOG\"\n"
            "exit 97\n"
        ),
    }
    for name, body in wrappers.items():
        path = bindir / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)
    return bindir


class ProcessManager:
    """Own every fixture child and reap it on both success and failure."""

    def __init__(self) -> None:
        self.processes: list[subprocess.Popen[str]] = []

    def start(self, args: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        process = subprocess.Popen(args, **kwargs)
        self.processes.append(process)
        return process

    def stop(self, process: subprocess.Popen[str], timeout: float = 5) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=timeout)

    def close(self) -> None:
        for process in reversed(self.processes):
            try:
                self.stop(process)
            except (OSError, subprocess.TimeoutExpired):
                pass
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


class TcpEchoHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            line = self.rfile.readline(4096)
            if not line:
                return
            self.wfile.write(self.server.generation.encode("ascii") + b":" + line)
            self.wfile.flush()


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        if data.startswith(b"HOLD_"):
            return
        sock.sendto(self.server.generation.encode("ascii") + b":" + data,
                    self.client_address)


class ThreadedTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadedUdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class ClientFlow:
    """A persistent client socket in the nested client network namespace."""

    def __init__(self, children: ProcessManager, python: str, protocol: str,
                 source_ip: str | None = None) -> None:
        args = ["ip", "netns", "exec", TEST_NS, python, "-u", "-c", CLIENT_CODE,
                protocol, TARGET_IP, str(TARGET_PORT), source_ip or "-"]
        self.process = children.start(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, bufsize=1)
        self.selector = selectors.DefaultSelector()
        assert self.process.stdout is not None
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        ready = self._readline(12)
        require(ready.startswith("READY "), f"{protocol} client failed to start: {ready[:180]}")
        self.source_port = int(ready.split()[1])
        self.protocol = protocol

    def _readline(self, timeout: float) -> str:
        assert self.process.stdout is not None
        ready = self.selector.select(timeout)
        if not ready:
            raise FixtureError("timed out waiting for isolated client response")
        line = self.process.stdout.readline()
        if not line:
            detail = ""
            if self.process.stderr is not None:
                detail = self.process.stderr.read(500)
            raise FixtureError(f"isolated client exited: {detail}")
        return line.rstrip("\r\n")

    def request(self, payload: str) -> str:
        assert self.process.stdin is not None
        self.process.stdin.write("REQUEST " + payload + "\n")
        self.process.stdin.flush()
        return self._readline(12)

    def send_without_reply(self, payload: str, allow_icmp_error: bool = False) -> str:
        assert self.protocol == "udp"
        assert self.process.stdin is not None
        command = "NO_REPLY_ALLOW_ICMP" if allow_icmp_error else "NO_REPLY"
        self.process.stdin.write(command + " " + payload + "\n")
        self.process.stdin.flush()
        return self._readline(12)

    def close(self) -> None:
        try:
            if self.process.poll() is None and self.process.stdin is not None:
                self.process.stdin.write("QUIT\n")
                self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        self.selector.close()


CLIENT_CODE = r'''import errno, select, socket, sys
protocol, destination, raw_port, source = sys.argv[1:]
port = int(raw_port)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
sock.settimeout(8)
if source != "-":
    sock.bind((source, 0))
if protocol == "tcp":
    sock.connect((destination, port))
else:
    sock.connect((destination, port))
print("READY " + str(sock.getsockname()[1]), flush=True)
for line in sys.stdin:
    command, _, payload = line.rstrip("\r\n").partition(" ")
    if command == "QUIT":
        break
    if command in {"NO_REPLY", "NO_REPLY_ALLOW_ICMP"}:
        sock.send(payload.encode())
        readable, _, _ = select.select([sock], [], [], 0.5)
        if readable:
            try:
                response = sock.recv(4096)
            except OSError as error:
                allowed_errors = {
                    errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH,
                    errno.EACCES, errno.EHOSTDOWN, errno.EPROTO,
                }
                if command == "NO_REPLY_ALLOW_ICMP" and error.errno in allowed_errors:
                    print("NETWORK_ERROR " + str(error.errno), flush=True)
                    continue
                raise
            raise RuntimeError("unexpected application response: " + repr(response))
        print("NO_REPLY", flush=True)
        continue
    if command != "REQUEST":
        raise RuntimeError("unknown fixture client command")
    data = payload.encode()
    if protocol == "tcp":
        sock.sendall(data + b"\n")
        response = bytearray()
        while not response.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                raise RuntimeError("TCP proxy closed the client flow")
            response.extend(chunk)
        reply = bytes(response).rstrip(b"\r\n")
    else:
        sock.send(data)
        reply = sock.recv(4096)
    print(reply.decode("ascii", errors="replace"), flush=True)
sock.close()
'''


def start_echo_servers(root: Path) -> tuple[list[Any], list[threading.Thread]]:
    servers: list[Any] = []
    threads: list[threading.Thread] = []
    for generation, port in (("BASELINE", BASE_ECHO_PORT),
                             ("CANDIDATE", CANDIDATE_ECHO_PORT)):
        for server_class, handler in ((ThreadedTcpServer, TcpEchoHandler),
                                      (ThreadedUdpServer, UdpEchoHandler)):
            server = server_class(("127.0.0.1", port), handler)
            server.generation = generation
            servers.append(server)
            thread = threading.Thread(target=server.serve_forever, name=f"echo-{generation}-{port}",
                                      daemon=True)
            thread.start()
            threads.append(thread)
    return servers, threads


def stop_echo_servers(servers: list[Any], threads: list[threading.Thread]) -> None:
    for server in servers:
        try:
            server.shutdown()
        except Exception:
            pass
        server.server_close()
    for thread in threads:
        thread.join(timeout=2)


def process_start_time(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    end_comm = raw.rfind(")")
    fields = raw[end_comm + 2:].split()
    require(len(fields) > 19, "could not read process start time")
    return fields[19]


def assert_alive(process: subprocess.Popen[str], expected_start: str, label: str) -> None:
    require(process.poll() is None, f"{label} sing-box process exited")
    require(process_start_time(process.pid) == expected_start,
            f"{label} sing-box process identity changed")


def listener_pids(protocol: str, port: int) -> set[int]:
    flag = "-t" if protocol == "tcp" else "-u"
    listing = output(["ss", "-Hlnp", flag], timeout=10)
    pids: set[int] = set()
    for line in listing.splitlines():
        if re.search(rf":{port}(?:\s|$)", line):
            pids.update(int(value) for value in re.findall(r"pid=(\d+)", line))
    return pids


def wait_listener(protocol: str, port: int, pid: int, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if listener_pids(protocol, port) == {pid}:
            return
        time.sleep(0.1)
    raise FixtureError(f"sing-box PID did not own the expected {protocol} listener on {port}")


def flow_row(conntrack: str, protocol: str, source_port: int,
             required: bool = True) -> str | None:
    result = command([
        conntrack, "-L", "-f", "ipv4", "-p", protocol,
        "--orig-src", CLIENT_IP if source_port >= 0 else UNOWNED_IP,
        "--orig-dst", TARGET_IP, "--sport", str(abs(source_port)),
        "--dport", str(TARGET_PORT),
    ], timeout=10, check=False)
    rows = [line for line in result.stdout.splitlines()
            if line.startswith(protocol + " ") and "src=" + (CLIENT_IP if source_port >= 0 else UNOWNED_IP) in line]
    require(result.returncode == 0, f"conntrack query failed: {result.stderr.strip()[:500]}")
    if not rows and not required:
        return None
    if not rows:
        diagnostic = command([conntrack, "-L", "-f", "ipv4", "-o", "extended"],
                             timeout=10, check=False)
        listing = diagnostic.stdout.strip()[:2400] or "<empty>"
        raise FixtureError(
            f"expected one {protocol} conntrack row, found 0; isolated conntrack listing: {listing}")
    require(len(rows) == 1, f"expected one {protocol} conntrack row, found {len(rows)}")
    return rows[0]


def mark_value(row: str) -> int:
    match = re.search(r"\bmark=(0x[0-9a-fA-F]+|[0-9]+)", row)
    require(match is not None, "conntrack output omitted the connection mark")
    return int(match.group(1), 0)


def update_flow_mark(conntrack: str, protocol: str, source_port: int, value_mask: str) -> None:
    command([
        conntrack, "-U", "-f", "ipv4", "-p", protocol,
        "--orig-src", CLIENT_IP, "--orig-dst", TARGET_IP,
        "--sport", str(source_port), "--dport", str(TARGET_PORT), "--mark", value_mask,
    ], timeout=10)


def mark_cookie(conntrack: str, protocol: str, source_port: int, expected: int) -> int:
    row = flow_row(conntrack, protocol, source_port)
    mark = mark_value(row)
    require(mark & CONNMARK_MASK == expected,
            f"{protocol} source port {source_port} has unexpected generation cookie {mark:#x}")
    return mark


def assert_udp_state(row: str, unreplied: bool, label: str) -> None:
    require(("[UNREPLIED]" in row) == unreplied,
            f"{label} UDP flow did not have expected conntrack state")


def generation_state(active_port: int, ports: list[int]) -> dict[str, Any]:
    return {"version": 1, "activePort": active_port,
            "generations": [{"port": port} for port in ports]}


def write_singbox_config(root: Path, port: int, echo_port: int) -> Path:
    config = {
        "log": {"level": "error", "timestamp": False},
        "inbounds": [{
            "type": "tproxy", "tag": "isolated-tproxy",
            "listen": "0.0.0.0", "listen_port": port,
        }],
        "outbounds": [{
            "type": "direct", "tag": "isolated-echo",
        }],
        "route": {"final": "isolated-echo",
                  "rules": [{
                      "inbound": ["isolated-tproxy"],
                      "action": "route",
                      "outbound": "isolated-echo",
                      "override_address": "127.0.0.1",
                      "override_port": echo_port,
                  }]},
    }
    path = root / f"sing-box-{port}.json"
    path.write_text(json.dumps(config, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)
    return path


def start_singbox(children: ProcessManager, binary: str, config: Path,
                  log_path: Path) -> subprocess.Popen[str]:
    log_handle = log_path.open("ab", buffering=0)
    process = children.start([binary, "run", "-c", str(config)], stdin=subprocess.DEVNULL,
                             stdout=log_handle, stderr=subprocess.STDOUT, text=True,
                             close_fds=True)
    return process


def setup_veth_and_routes() -> None:
    command(["sysctl", "-w", "net.ipv4.ip_forward=0"])
    forwarded = output(["sysctl", "-n", "net.ipv4.ip_forward"]).strip()
    require(forwarded == "0", "isolated gateway could not disable IP forwarding")
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "netns", "add", TEST_NS])
    command(["ip", "link", "add", "wg0", "type", "veth", "peer", "name", "c0"])
    command(["ip", "link", "set", "c0", "netns", TEST_NS])
    command(["ip", "addr", "add", GATEWAY_IP + "/24", "dev", "wg0"])
    command(["ip", "link", "set", "wg0", "up"])
    command(["ip", "netns", "exec", TEST_NS, "ip", "link", "set", "lo", "up"])
    command(["ip", "netns", "exec", TEST_NS, "ip", "addr", "add", CLIENT_IP + "/24", "dev", "c0"])
    command(["ip", "netns", "exec", TEST_NS, "ip", "addr", "add", UNOWNED_IP + "/24", "dev", "c0"])
    command(["ip", "netns", "exec", TEST_NS, "ip", "addr", "add", INACTIVE_IP + "/24", "dev", "c0"])
    command(["ip", "netns", "exec", TEST_NS, "ip", "link", "set", "c0", "up"])
    command(["ip", "netns", "exec", TEST_NS, "ip", "route", "add", "default", "via", GATEWAY_IP])
    default_route = output(["ip", "-4", "route", "show", "default"]).strip()
    require(not default_route, "isolated gateway unexpectedly has a public/default route")
    forwarded = output(["sysctl", "-n", "net.ipv4.ip_forward"]).strip()
    require(forwarded == "0", "isolated gateway unexpectedly has IP forwarding enabled")
    command(["ip", "-4", "rule", "add", "fwmark", "0x178/0xffffffff", "table", "178"])
    command(["ip", "-4", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "178"])


def init_owned_chains(routes: Any) -> None:
    for table, chain, parent in (
        ("filter", "NIUSU_WGM_IN", "INPUT"),
        ("filter", "NIUSU_WGM_FWD", "FORWARD"),
        ("mangle", "NIUSU_WGM_PRE", "PREROUTING"),
    ):
        args = ["iptables", "-w", "5"]
        if table != "filter":
            args.extend(["-t", table])
        command([*args, "-N", chain])
        jump = [*args, "-I", parent, "1", "-i", "wg0", "-j", chain]
        command(jump)
    # Register conntrack hooks before the first TPROXY packet arrives.
    command(["iptables", "-w", "5", "-I", "INPUT", "1", "-i", "wg0",
             "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"])
    # Markers must stay under the fixture root, never under a host-owned path.


def install_firewall(routes: Any, peers: dict[str, dict[str, str]],
                     active_sources: list[str], state: dict[str, Any] | None) -> None:
    routes._sync_firewall(peers, active_sources=active_sources, hotload_state=state)


def route_evidence() -> dict[str, str]:
    rules = output(["ip", "-4", "rule", "show"])
    table = output(["ip", "-4", "route", "show", "table", "178"])
    require(re.search(r"fwmark 0x178(?:/0xffffffff)?\s+.*lookup 178", rules) is not None,
            "policy rule for nfmark 0x178 is missing")
    require("local default dev lo" in table, "table 178 lacks the local default route")
    return {"ipRule": rules.strip(), "table178": table.strip()}


def managed_jump_packets() -> int:
    listing = output(["iptables", "-t", "mangle", "-L", "NIUSU_WGM_PRE", "-n", "-v", "-x"])
    for line in listing.splitlines():
        fields = line.split()
        if (len(fields) >= 9 and fields[2] == "NIUSU_WG_HOT"
                and fields[7] in {CLIENT_IP, CLIENT_IP + "/32"}):
            return int(fields[0])
    raise FixtureError("managed source jump to NIUSU_WG_HOT was not found")


def verify_inactive_output_drop(children: ProcessManager) -> None:
    """Prove a gateway-originated connection to an inactive peer is dropped."""
    server_code = r'''import socket, sys
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((sys.argv[1], int(sys.argv[2])))
server.listen(1)
server.settimeout(3)
print("READY", flush=True)
try:
    conn, _ = server.accept()
except TimeoutError:
    print("BLOCKED", flush=True)
else:
    print("CONNECTED", flush=True)
    conn.close()
server.close()
'''
    server = children.start(
        ["ip", "netns", "exec", TEST_NS, sys.executable, "-u", "-c", server_code,
         INACTIVE_IP, str(INACTIVE_PROBE_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
    )
    assert server.stdout is not None
    ready = selectors.DefaultSelector()
    try:
        ready.register(server.stdout, selectors.EVENT_READ)
        require(ready.select(5), "inactive-peer probe server did not start")
        require(server.stdout.readline().strip() == "READY",
                "inactive-peer probe server failed to bind")
    finally:
        ready.close()

    probe_code = r'''import socket, sys
sock = socket.socket()
sock.settimeout(1)
try:
    sock.connect((sys.argv[1], int(sys.argv[2])))
except TimeoutError:
    print("BLOCKED")
else:
    print("CONNECTED")
sock.close()
'''
    probe = command([sys.executable, "-c", probe_code, INACTIVE_IP,
                     str(INACTIVE_PROBE_PORT)], timeout=5)
    require(probe.stdout.strip() == "BLOCKED",
            "gateway connected to a managed inactive peer; OUTPUT DROP did not block it")
    require(server.wait(timeout=5) == 0, "inactive-peer probe server failed")
    require(server.stdout.readline().strip() == "BLOCKED",
            "inactive peer received traffic despite the OUTPUT DROP rule")


def test(args: argparse.Namespace) -> dict[str, Any]:
    isolation = check_isolation(args.host_netns_inode)
    require(os.geteuid() == 0, "fixture must run as root inside the isolated namespace")
    candidate = Path(args.candidate_modules).resolve()
    if (candidate / "node-manager").is_dir():
        candidate = candidate / "node-manager"
    require((candidate / "wireguard_routes.py").is_file(), "candidate wireguard_routes.py missing")
    require((candidate / "wireguard_hotload.py").is_file(), "candidate wireguard_hotload.py missing")
    reference = Path(args.reference_modules).resolve() if args.reference_modules else None
    if reference and (reference / "node-manager").is_dir():
        reference = reference / "node-manager"

    binary = str(Path(args.sing_box).resolve())
    require(Path(binary).is_file() and os.access(binary, os.X_OK), "sing-box 1.13.18 binary missing")
    version = output([binary, "version"], timeout=10).strip()
    require("1.13.18" in version, "fixture requires the real sing-box 1.13.18 binary")
    real_iptables = require_program("iptables")
    real_restore = require_program("iptables-restore")
    conntrack = require_program("conntrack")
    require_program("ip")
    require_program("ss")
    require_program("mount")
    require_program("umount")
    iptables_version = output([real_iptables, "--version"], timeout=5).strip()
    require("legacy" in iptables_version.lower(), "fixture requires the legacy iptables frontend")
    command(["mount", "--make-rprivate", "/"], timeout=10)
    root_context = tempfile.TemporaryDirectory(prefix="wg-hotload-isolated-")
    root = Path(root_context.name)
    local_lock = root / "xtables.lock"
    local_lock.touch(mode=0o600)
    bind_mounted = False
    run_tmpfs_mounted = False
    netns_created = False
    children = ProcessManager()
    servers: list[Any] = []
    server_threads: list[threading.Thread] = []
    clients: list[ClientFlow] = []
    server_logs: list[Any] = []
    systemctl_log = root / "systemctl-guard.log"
    systemctl_log.touch(mode=0o600)
    try:
        command(["mount", "-t", "tmpfs", "-o", "mode=755,nosuid,nodev", "tmpfs", "/run"], timeout=10)
        run_tmpfs_mounted = True
        Path("/run/netns").mkdir(parents=True, exist_ok=True)
        Path("/run/xtables.lock").touch(mode=0o600)
        command(["mount", "--bind", str(local_lock), "/run/xtables.lock"], timeout=10)
        bind_mounted = True
        require(os.stat(local_lock).st_ino == os.stat("/run/xtables.lock").st_ino,
                "xtables lock was not bound to the fixture-local file")

        original_path = os.environ.get("PATH", "")
        wrapper_dir = private_tool_wrappers(root, real_iptables, real_restore)
        os.environ["PATH"] = str(wrapper_dir) + os.pathsep + original_path
        os.environ["WG_HOTLOAD_SYSTEMCTL_GUARD_LOG"] = str(systemctl_log)
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        os.environ["NODE_MANAGER_CONFIG"] = str(root / "node-manager.yaml")
        os.environ["NODE_MANAGER_USER_REGISTRY"] = str(root / "users.json")
        os.environ["NODE_MANAGER_WIREGUARD_PROXY_CONFIG"] = str(root / "proxy-config.json")
        os.environ["NODE_MANAGER_WIREGUARD_SINGBOX"] = binary
        (root / "node-manager.yaml").write_text(
            "node:\n  host: 127.0.0.1\nsecurity:\n  token: isolated-fixture-only\n"
            "singbox:\n  config: " + str(root / "node-config.json") + "\n"
            "wireguard:\n  enabled: true\n  interface: wg0\n",
            encoding="utf-8",
        )
        (root / "users.json").write_text(
            json.dumps({"version": 2, "users": {}, "expiredUsers": {}}), encoding="utf-8")

        sys.dont_write_bytecode = True
        sys.path.insert(0, str(candidate))
        if reference and reference != candidate:
            sys.path.insert(1, str(reference))
        module_dir = Path(__file__).resolve().parents[1] / "node-manager"
        if module_dir.resolve() not in [Path(item).resolve() for item in sys.path if item]:
            sys.path.append(str(module_dir))
        import wireguard_hotload as hotload  # noqa: E402
        import wireguard_routes as routes  # noqa: E402

        require(Path(hotload.__file__).resolve().parent == candidate,
                "wireguard_hotload was not imported from the candidate directory")
        require(Path(routes.__file__).resolve().parent == candidate,
                "wireguard_routes was not imported from the candidate directory")
        require(hasattr(hotload, "STATE_PATH"), "candidate hotload module lacks STATE_PATH")
        require(hasattr(routes, "OUTPUT_CHAIN_MARKER"), "candidate routes module lacks OUTPUT_CHAIN_MARKER")
        require(hasattr(routes, "HOTLOAD_CHAIN_MARKER"), "candidate routes module lacks HOTLOAD_CHAIN_MARKER")
        hotload.STATE_PATH = root / "hotload-state.json"
        routes.CONFIG_PATH = root / "base-proxy-config.json"
        routes.OUTPUT_CHAIN_MARKER = root / "reuse-output-owned"
        routes.HOTLOAD_CHAIN_MARKER = root / "hotload-chain-owned"

        servers, server_threads = start_echo_servers(root)
        setup_veth_and_routes()
        netns_created = True
        init_owned_chains(routes)
        peers = {
            "fixture-owned-peer": {"address": CLIENT_IP + "/32"},
            "fixture-inactive-peer": {"address": INACTIVE_IP + "/32"},
        }
        owned_sources = [CLIENT_IP + "/32"]

        baseline_config = write_singbox_config(root, BASE_PORT, BASE_ECHO_PORT)
        candidate_config = write_singbox_config(root, CANDIDATE_PORT, CANDIDATE_ECHO_PORT)
        for config_path in (baseline_config, candidate_config):
            checked = command([binary, "check", "-c", str(config_path)], timeout=30)
            require(checked.returncode == 0, "valid isolated sing-box configuration was rejected")

        baseline_log = (root / "baseline.log").open("ab", buffering=0)
        server_logs.append(baseline_log)
        baseline = children.start([binary, "run", "-c", str(baseline_config)],
                                  stdin=subprocess.DEVNULL, stdout=baseline_log,
                                  stderr=subprocess.STDOUT, close_fds=True)
        wait_listener("tcp", BASE_PORT, baseline.pid)
        wait_listener("udp", BASE_PORT, baseline.pid)
        baseline_started = process_start_time(baseline.pid)

        # A malformed candidate must be rejected while the baseline stays live.
        invalid_config = root / "invalid-candidate.json"
        invalid_config.write_text('{"inbounds":[{"type":"invalid-fixture-inbound"}]}',
                                  encoding="ascii")
        rejected = command([binary, "check", "-c", str(invalid_config)], timeout=30, check=False)
        require(rejected.returncode != 0, "invalid candidate unexpectedly passed sing-box validation")

        # Establish real client flows under the legacy single-listener rules.
        install_firewall(routes, peers, owned_sources, None)
        old_tcp = ClientFlow(children, sys.executable, "tcp")
        old_udp = ClientFlow(children, sys.executable, "udp")
        old_oneway_udp = ClientFlow(children, sys.executable, "udp")
        clients.extend((old_tcp, old_udp, old_oneway_udp))
        require(old_tcp.request("OLD_TCP_PRE") == "BASELINE:OLD_TCP_PRE",
                "legacy TCP flow did not reach the baseline listener")
        require(old_udp.request("OLD_UDP_PRE") == "BASELINE:OLD_UDP_PRE",
                "legacy replied UDP flow did not reach the baseline listener")
        require(old_oneway_udp.send_without_reply("HOLD_UDP_PRE") == "NO_REPLY",
                "one-way UDP setup unexpectedly received a reply")

        old_flows = {
            "tcp": old_tcp.source_port,
            "udpReplied": old_udp.source_port,
            "udpUnreplied": old_oneway_udp.source_port,
        }
        rows = {
            "tcp": flow_row(conntrack, "tcp", old_tcp.source_port),
            "udpReplied": flow_row(conntrack, "udp", old_udp.source_port),
            "udpUnreplied": flow_row(conntrack, "udp", old_oneway_udp.source_port),
        }
        require("ESTABLISHED" in rows["tcp"], "baseline TCP flow is not conntrack ESTABLISHED")
        assert_udp_state(rows["udpReplied"], False, "replied baseline")
        assert_udp_state(rows["udpUnreplied"], True, "one-way baseline")

        # Seed low bits so both the kernel CONNMARK rule and conntrack CLI update
        # must preserve them while assigning the generation cookie in the high byte.
        update_flow_mark(conntrack, "tcp", old_tcp.source_port, "0x00001234/0x0000ffff")
        update_flow_mark(conntrack, "udp", old_udp.source_port, "0x00001234/0x0000ffff")
        update_flow_mark(conntrack, "udp", old_oneway_udp.source_port, "0x00001234/0x0000ffff")
        for name, (proto, port) in {
            "tcp": ("tcp", old_tcp.source_port),
            "udpReplied": ("udp", old_udp.source_port),
            "udpUnreplied": ("udp", old_oneway_udp.source_port),
        }.items():
            require(mark_value(flow_row(conntrack, proto, port)) == LOW_MARK,
                    f"conntrack low-bit setup failed for {name}")

        assert_alive(baseline, baseline_started, "baseline")
        route_before = route_evidence()

        # First install the base-default generation. Existing established flows
        # are pinned by real iptables CONNMARK rules; an unreplied UDP flow needs
        # the same real masked conntrack update used by the migration.
        install_firewall(routes, peers, owned_sources, generation_state(BASE_PORT, [BASE_PORT]))
        require(old_tcp.request("OLD_TCP_BASE_RULE") == "BASELINE:OLD_TCP_BASE_RULE",
                "established TCP flow left the baseline during base marking")
        require(old_udp.request("OLD_UDP_BASE_RULE") == "BASELINE:OLD_UDP_BASE_RULE",
                "established UDP flow left the baseline during base marking")
        base_tcp_mark = mark_cookie(conntrack, "tcp", old_tcp.source_port, BASE_COOKIE)
        base_udp_mark = mark_cookie(conntrack, "udp", old_udp.source_port, BASE_COOKIE)
        held_row = flow_row(conntrack, "udp", old_oneway_udp.source_port)
        assert_udp_state(held_row, True, "pre-migration one-way")
        require(mark_value(held_row) == LOW_MARK,
                "unreplied UDP flow was unexpectedly packet-marked before migration")

        migration = command([
            conntrack, "-U", "-f", "ipv4", "--orig-src", CLIENT_IP,
            "--mark", "0x01000000/0xff000000",
        ], timeout=15)
        require(migration.returncode == 0, "masked legacy conntrack update failed")
        held_mark = mark_cookie(conntrack, "udp", old_oneway_udp.source_port, BASE_COOKIE)
        require(held_mark == (BASE_COOKIE | LOW_MARK),
                "masked conntrack update did not preserve low mark bits on UNREPLIED UDP")
        for name, (proto, port) in {
            "tcp": ("tcp", old_tcp.source_port),
            "udpReplied": ("udp", old_udp.source_port),
            "udpUnreplied": ("udp", old_oneway_udp.source_port),
        }.items():
            mark = mark_cookie(conntrack, proto, port, BASE_COOKIE)
            require(mark & 0x0000ffff == LOW_MARK,
                    f"generation mark update clobbered low bits for {name}")

        candidate_log = (root / "candidate.log").open("ab", buffering=0)
        server_logs.append(candidate_log)
        candidate_process = children.start(
            [binary, "run", "-c", str(candidate_config)], stdin=subprocess.DEVNULL,
            stdout=candidate_log, stderr=subprocess.STDOUT, close_fds=True)
        wait_listener("tcp", CANDIDATE_PORT, candidate_process.pid)
        wait_listener("udp", CANDIDATE_PORT, candidate_process.pid)
        candidate_started = process_start_time(candidate_process.pid)

        hot_state = generation_state(CANDIDATE_PORT, [BASE_PORT, CANDIDATE_PORT])
        install_firewall(routes, peers, owned_sources, hot_state)
        restore_calls: list[str] = []
        real_iptables_restore = routes._iptables_restore

        def count_iptables_restore(batch: str) -> None:
            restore_calls.append(batch)
            return real_iptables_restore(batch)

        routes._iptables_restore = count_iptables_restore
        try:
            install_firewall(routes, peers, owned_sources, hot_state)
        finally:
            routes._iptables_restore = real_iptables_restore
        identical_sync_restore_count = len(restore_calls)
        require(identical_sync_restore_count == 0,
                "identical hotload sync unexpectedly invoked iptables-restore")
        verify_inactive_output_drop(children)
        output_rules = output(["iptables", "-S", routes.OUTPUT_CHAIN])
        require(f"-d {INACTIVE_IP}/32 -j DROP" in output_rules,
                "inactive managed peer is missing its OUTPUT DROP rule")
        require(route_evidence() == route_before, "policy routing changed during generation promotion")
        require(listener_pids("tcp", BASE_PORT) == {baseline.pid}
                and listener_pids("udp", BASE_PORT) == {baseline.pid},
                "baseline listener PID changed at promotion")
        require(listener_pids("tcp", CANDIDATE_PORT) == {candidate_process.pid}
                and listener_pids("udp", CANDIDATE_PORT) == {candidate_process.pid},
                "candidate listener PID mismatch")

        # Existing TCP and replied/unreplied UDP sessions must remain on PID 61037.
        require(old_tcp.request("OLD_TCP_AFTER") == "BASELINE:OLD_TCP_AFTER",
                "existing TCP flow moved away from the baseline listener")
        require(old_udp.request("OLD_UDP_AFTER") == "BASELINE:OLD_UDP_AFTER",
                "existing replied UDP flow moved away from the baseline listener")
        require(old_oneway_udp.request("RELEASE_UDP_AFTER") == "BASELINE:RELEASE_UDP_AFTER",
                "migrated UNREPLIED UDP flow did not resume on the baseline listener")
        for name, (proto, port) in {
            "tcp": ("tcp", old_tcp.source_port),
            "udpReplied": ("udp", old_udp.source_port),
            "udpUnreplied": ("udp", old_oneway_udp.source_port),
        }.items():
            mark = mark_cookie(conntrack, proto, port, BASE_COOKIE)
            require(mark & 0x0000ffff == LOW_MARK,
                    f"old flow mark changed after promotion: {name}")

        new_tcp = ClientFlow(children, sys.executable, "tcp")
        new_udp = ClientFlow(children, sys.executable, "udp")
        clients.extend((new_tcp, new_udp))
        require(new_tcp.request("NEW_TCP_CANDIDATE") == "CANDIDATE:NEW_TCP_CANDIDATE",
                "new TCP connection did not reach candidate")
        require(new_udp.request("NEW_UDP_CANDIDATE") == "CANDIDATE:NEW_UDP_CANDIDATE",
                "new UDP connection did not reach candidate")
        mark_cookie(conntrack, "tcp", new_tcp.source_port, CANDIDATE_COOKIE)
        mark_cookie(conntrack, "udp", new_udp.source_port, CANDIDATE_COOKIE)
        assert_alive(baseline, baseline_started, "baseline")
        assert_alive(candidate_process, candidate_started, "candidate")

        # A source not owned by the WG peer registry must never enter the hot chain.
        before_unowned = managed_jump_packets()
        unowned_udp = ClientFlow(children, sys.executable, "udp", source_ip=UNOWNED_IP)
        clients.append(unowned_udp)
        unowned_probe = unowned_udp.send_without_reply(
            "UNOWNED_SHOULD_NOT_PROXY", allow_icmp_error=True)
        require(unowned_probe == "NO_REPLY" or unowned_probe.startswith("NETWORK_ERROR "),
                "unowned source received an application response or invalid network result")
        after_unowned = managed_jump_packets()
        require(before_unowned == after_unowned,
                "unowned source incremented the owned-source hotload jump")
        unowned_row = flow_row(conntrack, "udp", -unowned_udp.source_port, required=False)
        unowned_mark = mark_value(unowned_row) if unowned_row is not None else None
        require(unowned_mark is None or unowned_mark & CONNMARK_MASK == 0,
                "unowned source was assigned a WireGuard generation cookie")

        # Simulate candidate death after promotion: pinned old flows stay healthy
        # on their original process, whose PID and start time must remain stable.
        children.stop(candidate_process)
        require(listener_pids("tcp", CANDIDATE_PORT) == set()
                and listener_pids("udp", CANDIDATE_PORT) == set(),
                "failed candidate still owns a listener")
        assert_alive(baseline, baseline_started, "baseline after candidate failure")
        require(old_tcp.request("OLD_TCP_AFTER_CANDIDATE_FAILURE")
                == "BASELINE:OLD_TCP_AFTER_CANDIDATE_FAILURE",
                "candidate failure disrupted the existing TCP flow")
        require(old_udp.request("OLD_UDP_AFTER_CANDIDATE_FAILURE")
                == "BASELINE:OLD_UDP_AFTER_CANDIDATE_FAILURE",
                "candidate failure disrupted the existing replied UDP flow")
        require(old_oneway_udp.request("OLD_UNREPLIED_UDP_AFTER_FAILURE")
                == "BASELINE:OLD_UNREPLIED_UDP_AFTER_FAILURE",
                "candidate failure disrupted the migrated one-way UDP flow")

        rules = output(["iptables", "-t", "mangle", "-S", "NIUSU_WGM_PRE"])
        hotload_rules = output(["iptables", "-t", "mangle", "-S", routes.HOTLOAD_CHAIN])
        all_hotload_rules = rules + "\n" + hotload_rules
        for expected in ("--on-port 61037", "--on-port 61038", "0x178/0xffffffff"):
            require(expected in all_hotload_rules, f"hotload firewall evidence missing {expected}")
        require("" == systemctl_log.read_text(encoding="utf-8"),
                "fixture attempted a systemctl operation")

        source_hashes = {}
        for filename in ("wireguard_routes.py", "wireguard_hotload.py"):
            source_hashes[filename] = hashlib.sha256((candidate / filename).read_bytes()).hexdigest()
        return {
            "successful": True,
            "isolation": isolation,
            "mountPrivateAndXtablesBound": True,
            "singBoxVersion": version,
            "iptablesVersion": iptables_version,
            "conntrackPath": conntrack,
            "noGatewayDefaultRoute": True,
            "vethGatewayAddress": GATEWAY_IP,
            "clientDefaultGateway": GATEWAY_IP,
            "ipForwardingDisabled": True,
            "realProcesses": {"baselinePid": baseline.pid, "candidatePid": candidate_process.pid},
            "oldFlows": old_flows,
            "oldConntrackMarks": {
                "tcp": f"{base_tcp_mark:#010x}",
                "udpReplied": f"{base_udp_mark:#010x}",
                "udpUnreplied": f"{held_mark:#010x}",
            },
            "candidateConntrackMarks": {
                "tcp": f"{mark_cookie(conntrack, 'tcp', new_tcp.source_port, CANDIDATE_COOKIE):#010x}",
                "udp": f"{mark_cookie(conntrack, 'udp', new_udp.source_port, CANDIDATE_COOKIE):#010x}",
            },
            "unownedProbeResult": unowned_probe,
            "unownedConntrackMark": f"{unowned_mark:#010x}" if unowned_mark is not None else None,
            "identicalHotloadSyncRestoreCount": identical_sync_restore_count,
            "checks": {
                "invalidCandidateRejected": True,
                "oldTcpAndRepliedUdpMarkedByFirewall": True,
                "unrepliedUdpMarkedByMaskedConntrackUpdate": True,
                "conntrackMaskPreservedLowBits": True,
                "oldFlowsStayedOnBaselinePid": True,
                "newTcpUdpReachedCandidatePid": True,
                "identicalHotloadSyncSkippedRestore": True,
                "candidateFailureLeftOldFlowsWorking": True,
                "unownedSourceSkippedHotload": True,
                "inactivePeerOutputDropped": True,
                "nfmark0x178RoutesViaTable178": True,
                "hostSystemctlNotInvoked": True,
            },
            "routeEvidence": route_evidence(),
            "hotloadFirewallEvidence": {
                "parentChain": rules.strip(),
                "generationChain": hotload_rules.strip(),
                "inactiveOutputChain": output_rules.strip(),
            },
            "sourceHashes": source_hashes,
        }
    finally:
        for client in reversed(clients):
            client.close()
        children.close()
        stop_echo_servers(servers, server_threads)
        if netns_created:
            command(["ip", "netns", "del", TEST_NS], timeout=10, check=False)
        if bind_mounted:
            command(["umount", "/run/xtables.lock"], timeout=10, check=False)
        if run_tmpfs_mounted:
            command(["umount", "/run"], timeout=10, check=False)
        for handle in server_logs:
            try:
                handle.close()
            except OSError:
                pass
        root_context.cleanup()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host_netns_inode", help="host namespace inode from readlink /proc/self/ns/net")
    parser.add_argument("candidate_modules", help="directory containing candidate wireguard modules")
    parser.add_argument(
        "--reference-modules",
        default=os.environ.get("WG_HOTLOAD_REFERENCE_MODULES",
                               "/opt/node-manager-releases/node-manager-20261010-source-runtime-v3/node-manager"),
        help="read-only source path used only for unchanged Node Manager dependencies",
    )
    parser.add_argument(
        "--sing-box", default=os.environ.get("WG_HOTLOAD_SINGBOX", "/usr/bin/sing-box1.13.18"),
        help="real sing-box 1.13.18 executable",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = test(args)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({"successful": False, "error": str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
