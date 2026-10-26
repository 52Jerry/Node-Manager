"""One file-versioned, read-only snapshot for connection detail queries.

Mutation paths keep using fresh dictionaries. This cache is used only while
holding the existing configuration lock, and never caches endpoint responses,
expiration decisions, or authorization results.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


class ConnectionSnapshot:
    def __init__(self, data: dict, registry: dict):
        self.data = data
        self.registry = registry
        self.users: dict[tuple[int, str], dict[str, tuple[int, dict]]] = {}
        for inbound in data.get("inbounds", []):
            for field in ("name", "username"):
                index: dict[str, tuple[int, dict]] = {}
                for position, user in enumerate(inbound.get("users", [])):
                    value = user.get(field)
                    if isinstance(value, str):
                        index.setdefault(value, (position, user))
                self.users[(id(inbound), field)] = index
        self.outbounds: dict[str, dict] = {}
        for outbound in data.get("outbounds", []):
            tag = outbound.get("tag")
            if isinstance(tag, str):
                self.outbounds.setdefault(tag, outbound)

    def find(self, inbound: dict, names: set[str], field: str = "name") -> dict | None:
        index = self.users.get((id(inbound), field), {})
        matches = [index[name] for name in names if name in index]
        return min(matches, key=lambda entry: entry[0])[1] if matches else None


class ConnectionSnapshotCache:
    def __init__(self):
        self._key: tuple | None = None
        self._snapshot: ConnectionSnapshot | None = None

    @staticmethod
    def _version(path: Path, optional: bool = False) -> tuple | None:
        try:
            value = path.stat()
        except FileNotFoundError:
            if optional:
                return None
            raise
        return (str(path), value.st_dev, value.st_ino, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)

    def get(self, config_path: Path, registry_path: Path,
            load_config: Callable[[], dict], load_registry: Callable[[], dict]) -> ConnectionSnapshot:
        key = (self._version(config_path), self._version(registry_path, optional=True),
               load_config, load_registry)
        if key != self._key or self._snapshot is None:
            # Publish only after both files parse. Never serve a previous
            # credential snapshot if a changed file is invalid/unreadable.
            snapshot = ConnectionSnapshot(load_config(), load_registry())
            self._snapshot, self._key = snapshot, key
        return self._snapshot
