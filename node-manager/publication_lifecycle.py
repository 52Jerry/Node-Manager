"""Serialize publication maintenance with the existing Node Manager config lock."""
import fcntl
import json
import pathlib
import subprocess
import sys
import time


def main():
    spec_path, action = sys.argv[1:]
    if action not in {"boot", "collect"}:
        raise ValueError("unsupported_lifecycle_action")
    spec = json.loads(pathlib.Path(spec_path).read_text())
    root = pathlib.Path(__file__).parent
    with open("/run/lock/node-manager-singbox.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        command = [sys.executable, str(root / "vless_publication.py"), "--spec", spec_path]
        if action == "boot":
            deadline = time.monotonic() + 45
            while True:
                result = subprocess.run(command + ["boot"], capture_output=True, text=True, timeout=180)
                if result.returncode == 0:
                    print(result.stdout.strip())
                    return
                if time.monotonic() >= deadline:
                    raise RuntimeError("vless_boot_publication_not_ready")
                time.sleep(1)
        else:
            result = subprocess.run(command + ["collect"], capture_output=True, text=True, timeout=180)
            if result.returncode:
                raise RuntimeError("vless_generation_maintenance_needs_review")
            print(result.stdout.strip())


if __name__ == "__main__":
    main()
