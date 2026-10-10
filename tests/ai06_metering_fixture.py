"""Finite loopback-only VLESS metering experiment with an independent TCP oracle.

Requires an explicitly selected sing-box executable. Never reads live configs,
uses production credentials, activates quota enforcement or downloads anything.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
from monitor.cumulative_meter import CumulativeMeter


def exact(stream, size):
    parts = []
    while size:
        part = stream.recv(min(size, 65536))
        if not part:
            raise EOFError("incomplete payload")
        parts.append(part)
        size -= len(part)
    return b"".join(parts)


class Origin(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 64

    def __init__(self):
        super().__init__(("127.0.0.1", 0), OriginHandler)
        self.lock = threading.Lock()
        self.upload = self.download = 0
        self.errors = []

    def record(self, upload=0, download=0):
        with self.lock:
            self.upload += upload
            self.download += download

    def totals(self):
        with self.lock:
            if self.errors:
                raise AssertionError(self.errors)
            return {"upload": self.upload, "download": self.download}


class OriginHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                first = self.request.recv(1)
                if not first:
                    return
                header = first + exact(self.request, 15)
                up, down = struct.unpack("!QQ", header)
                if max(up, down) > 8 * 1024 * 1024:
                    raise ValueError("fixture payload too large")
                data = exact(self.request, up)
                if data != b"U" * up:
                    raise AssertionError("upload content mismatch")
                self.server.record(upload=16 + up)
                self.request.sendall(b"D" * down)
                self.server.record(download=down)
        except Exception as exc:
            with self.server.lock:
                self.server.errors.append(type(exc).__name__)


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def snapshot(port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(f"http://127.0.0.1:{port}/connections",
                                     headers={"Authorization": "Bearer ai06-fake-local-secret"})
    with opener.open(request, timeout=2) as response:
        value = json.load(response)
    assert all(type(value[key]) is int for key in ("uploadTotal", "downloadTotal"))
    return value


def counters(value):
    return {"upload": value["uploadTotal"], "download": value["downloadTotal"]}


@contextmanager
def runtime(binary, configuration, directory, name, ready):
    config_path = directory / f"{name}.json"
    config_path.write_text(json.dumps(configuration), encoding="utf-8")
    check = subprocess.run([str(binary), "check", "-c", str(config_path)],
                           capture_output=True, text=True, timeout=15)
    if check.returncode:
        raise AssertionError(check.stderr)
    with (directory / f"{name}.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen([str(binary), "run", "-c", str(config_path)],
                                   stdout=log, stderr=log,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise AssertionError(f"{name} exited {process.returncode}")
                try:
                    ready()
                    break
                except (OSError, ValueError):
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"{name} start timeout")
                    time.sleep(0.05)
            yield process
        except BaseException:
            log.flush()
            print((directory / f"{name}.log").read_text(encoding="utf-8"), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def socks_session(port, destination):
    stream = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        stream.sendall(b"\x05\x01\x00")
        assert exact(stream, 2) == b"\x05\x00"
        stream.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", destination))
        reply = exact(stream, 4)
        assert reply[:2] == b"\x05\x00"
        if reply[3] == 1:
            exact(stream, 6)
        elif reply[3] == 4:
            exact(stream, 18)
        else:
            exact(stream, exact(stream, 1)[0] + 2)
        return stream
    except BaseException:
        stream.close()
        raise


def exchange(stream, up, down):
    stream.sendall(struct.pack("!QQ", up, down) + b"U" * up)
    assert exact(stream, down) == b"D" * down
    return {"upload": up + 16, "download": down}


def difference(after, before):
    return {key: after[key] - before[key] for key in ("upload", "download")}


def settled(port, expected):
    deadline = time.monotonic() + 5
    while True:
        value = snapshot(port)
        if not value["connections"] and counters(value) == expected:
            return value
        if time.monotonic() > deadline:
            raise AssertionError({"expected": expected, "actual": counters(value),
                                  "active": len(value["connections"])})
        time.sleep(0.01)


def comparison(name, oracle, native, sampled, duration):
    return {"scenario": name, "seconds": round(duration, 6), "oracle": oracle,
            "native": native, "activeOnlySampled": sampled,
            "nativeError": {key: (native[key] - oracle[key]) / oracle[key] for key in oracle},
            "activeOnlyError": {key: (sampled[key] - oracle[key]) / oracle[key] for key in oracle}}


def run(binary, expected_version):
    version = subprocess.check_output([str(binary), "version"], text=True, timeout=10).strip()
    if version.splitlines()[0] != f"sing-box version {expected_version}":
        raise ValueError("runtime version mismatch; select explicitly, never relabel evidence")
    vless, socks, api = free_port(), free_port(), free_port()
    fake_uuid = "00000000-0000-4000-8000-000000000006"
    server = {"log": {"level": "error"}, "inbounds": [{"type": "vless", "tag": "fixture",
              "listen": "127.0.0.1", "listen_port": vless,
              "users": [{"name": "ai06-fake-user", "uuid": fake_uuid}]}],
              "outbounds": [{"type": "direct", "tag": "node-manager-out:ai06-fake-user"}],
              "route": {"final": "node-manager-out:ai06-fake-user"},
              "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{api}",
                                              "secret": "ai06-fake-local-secret"}}}
    client = {"log": {"level": "error"}, "inbounds": [{"type": "socks", "tag": "fixture-client",
              "listen": "127.0.0.1", "listen_port": socks}],
              "outbounds": [{"type": "vless", "tag": "fixture-vless", "server": "127.0.0.1",
                             "server_port": vless, "uuid": fake_uuid}],
              "route": {"final": "fixture-vless"}}
    results = []
    origin = Origin()
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    destination = origin.server_address[1]
    try:
        with tempfile.TemporaryDirectory(prefix="ai06-meter-") as temporary:
            directory = Path(temporary)
            meter = CumulativeMeter(directory / "meter.sqlite")

            def client_ready():
                with socket.create_connection(("127.0.0.1", socks), timeout=1):
                    pass

            with runtime(binary, client, directory, "client", client_ready):
                with runtime(binary, server, directory, "server1", lambda: snapshot(api)):
                    for name, jobs in (("short_below_2_seconds", [(4096, 12288)]),
                                       ("concurrent_16", [(8192 + i * 17, 16384 + i * 31) for i in range(16)])):
                        before = origin.totals()
                        native_before = counters(snapshot(api))
                        start = time.perf_counter()

                        def job(pair):
                            with socks_session(socks, destination) as stream:
                                exchange(stream, *pair)

                        with ThreadPoolExecutor(max_workers=16) as pool:
                            list(pool.map(job, jobs))
                        duration = time.perf_counter() - start
                        after = origin.totals()
                        final = settled(api, after)
                        oracle = difference(after, before)
                        results.append(comparison(name, oracle, difference(counters(final), native_before),
                                                  {"upload": 0, "download": 0}, duration))
                    before = origin.totals()
                    native_before = counters(snapshot(api))
                    start = time.perf_counter()
                    with socks_session(socks, destination) as stream:
                        exchange(stream, 65536, 131072)
                        time.sleep(2.1)
                        mid = snapshot(api)
                        assert len(mid["connections"]) == 1
                        sampled = {key: sum(item[key] for item in mid["connections"])
                                   for key in ("upload", "download")}
                        exchange(stream, 32768, 98304)
                    after = origin.totals()
                    final = settled(api, after)
                    duration = time.perf_counter() - start
                    results.append(comparison("long_connection_closed_tail", difference(after, before),
                                              difference(counters(final), native_before), sampled, duration))
                    ledger_start = time.perf_counter()
                    for sequence in range(1, 101):
                        meter.ingest(node="ai06-local", epoch="controlled-start-1", generation=1,
                                     sequence=sequence, counters={"__node__": counters(final)})
                    ledger_seconds = time.perf_counter() - ledger_start
                    final_first_epoch = counters(final)
                # Only this fixture controls process lifetime: its epoch is externally known.
                with runtime(binary, server, directory, "server2", lambda: snapshot(api)) as process:
                    assert counters(snapshot(api)) == {"upload": 0, "download": 0}
                    before = origin.totals()
                    with socks_session(socks, destination) as stream:
                        exchange(stream, 2048, 6144)
                    second_expected = difference(origin.totals(), before)
                    final = settled(api, second_expected)
                    restart = meter.ingest(node="ai06-local", epoch="controlled-start-2", generation=2,
                                           sequence=1, counters={"__node__": counters(final)})
                    expected = {key: final_first_epoch[key] + second_expected[key]
                                for key in second_expected}
                    totals = meter.totals("__node__")
                    assert all(totals[key] == expected[key] for key in expected)
                    # The independent endpoint sees this tail, but the durable
                    # ledger intentionally does not receive another API sample.
                    with socks_session(socks, destination) as stream:
                        exchange(stream, 512, 1536)
                    process.kill()
                    process.wait(timeout=5)
                with runtime(binary, server, directory, "server3", lambda: snapshot(api)):
                    crash_restart = meter.ingest(
                        node="ai06-local", epoch="controlled-start-3", generation=3,
                        sequence=1, counters={"__node__": counters(snapshot(api))})
                    missing = difference(origin.totals(), meter.totals("__node__"))
                    assert missing == {"upload": 528, "download": 1536}
                    size = meter.path.stat().st_size
            return {"runtime": version, "runtimeSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "scope": "loopback VLESS TCP payload only, no TLS/Reality or UDP, node-wide not per-user",
                    "results": results, "restart": restart, "ledgerTotals": totals,
                    "crashBeforePersist": {"restart": crash_restart, "missingBytes": missing,
                                           "exactBillingRecovered": False},
                    "ledger100BatchesSeconds": round(ledger_seconds, 6), "ledgerBytes": size,
                    "independentOrigin": origin.totals(), "resources": "RSS/FD/load trend not measured",
                    "productionAcceptance": False, "toleranceApproved": False}
    finally:
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--expected-version", default="1.13.18")
    args = parser.parse_args()
    print(json.dumps(run(args.sing_box.resolve(), args.expected_version), indent=2))
