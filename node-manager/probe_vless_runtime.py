"""Real local Reality/Vision proof using a non-customer, destination-restricted identity."""

from __future__ import annotations
import base64, ctypes, hashlib, http.server, json, pathlib, socket, subprocess, sys, tempfile, threading, time, uuid, os, signal
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


def main():
    path = pathlib.Path(sys.argv[1])
    config = json.loads(path.read_text())
    inbound = config["inbounds"][0]
    user = next(
        u
        for u in inbound["users"]
        if u["name"].startswith("niusu-internal-publication:")
    )
    reality = (inbound.get("tls") or {}).get("reality")
    public = None
    if reality:
        key = reality["private_key"]
        key = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        public = (
            base64.urlsafe_b64encode(
                X25519PrivateKey.from_private_bytes(key)
                .public_key()
                .public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            )
            .decode()
            .rstrip("=")
        )
    elif "--allow-plain-isolated-test" not in sys.argv:
        raise RuntimeError("reality_required")
    token = uuid.uuid4().hex.encode()
    server = None
    client = None

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(token)))
            self.end_headers()
            self.wfile.write(token)

    def call(port):
        def exact(s, n):
            b = b""
            while len(b) < n:
                part = s.recv(n - len(b))
                if not part:
                    raise RuntimeError("probe_eof")
                b += part
            return b

        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.settimeout(3)
            s.sendall(b"\x05\x01\x00")
            assert exact(s, 2) == b"\x05\x00"
            s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + (61499).to_bytes(2, "big"))
            h = exact(s, 4)
            assert h[1] == 0
            if h[3] == 1:
                exact(s, 6)
            elif h[3] == 4:
                exact(s, 18)
            else:
                exact(s, exact(s, 1)[0] + 2)
            s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            body = b""
            while True:
                part = s.recv(4096)
                if not part:
                    break
                body += part
                if len(body) > 65536:
                    raise RuntimeError("invalid_probe_response")
            assert body.split(b"\r\n\r\n", 1)[1] == token, "vless_payload_mismatch"

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 61499), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        cfg = {
            "log": {"disabled": True},
            "inbounds": [],
            "outbounds": [],
            "route": {"rules": []},
        }
        ports = []
        for tag, ident in [("valid", user["uuid"]), ("invalid", str(uuid.uuid4()))]:
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            ports.append(port)
            cfg["inbounds"].append(
                {
                    "type": "socks",
                    "tag": tag,
                    "listen": "127.0.0.1",
                    "listen_port": port,
                }
            )
            outbound = {
                "type": "vless",
                "tag": tag,
                "server": "127.0.0.1",
                "server_port": inbound["listen_port"],
                "uuid": ident,
                "flow": user.get("flow", ""),
            }
            if reality:
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": inbound["tls"].get("server_name")
                    or reality["handshake"]["server"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": public,
                        "short_id": reality.get("short_id", [""])[0],
                    },
                }
            cfg["outbounds"].append(outbound)
            cfg["route"]["rules"].append({"inbound": [tag], "outbound": tag})

        def parent_death():
            ctypes.CDLL(None).prctl(1, signal.SIGTERM)

        client = subprocess.Popen(
            ["/usr/bin/sing-box", "run", "-c", "stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=parent_death,
        )
        client.stdin.write(json.dumps(cfg).encode())
        client.stdin.close()
        deadline = time.monotonic() + 3
        while True:
            try:
                with socket.create_connection(("127.0.0.1", ports[0]), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("probe_client_not_ready")
                time.sleep(0.05)
        call(ports[0])
        rejected = False
        try:
            call(ports[1])
        except (OSError, ValueError, IndexError, AssertionError, RuntimeError):
            rejected = True
        if not rejected:
            raise RuntimeError("invalid_uuid_accepted")
        canonical = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        return {
            "passed": True,
            "configHash": hashlib.sha256(canonical).hexdigest(),
            "realityVision": bool(reality),
            "invalidUuidRejected": True,
        }
    finally:
        if client:
            client.terminate()
            try:
                client.wait(timeout=2)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=2)
        if server:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    try:
        print(json.dumps(main()))
    except Exception as exc:
        print(json.dumps({"passed": False, "reason": type(exc).__name__}))
        raise SystemExit(1)
