"""Isolated monotonic counter ledger; never changes routing or enforces quotas.

An external collector supplies a trusted process epoch and serialized sequence.
Counters must be absolute, non-resetting values, not periodic deltas. Node-wide
Clash counters cannot be attributed to individual users.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class CounterRejected(ValueError):
    pass


class CumulativeMeter:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        # Create with restricted permissions before SQLite can put counters in it.
        if not self.path.exists():
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS batches (
                    node TEXT NOT NULL, epoch TEXT NOT NULL, sequence INTEGER NOT NULL,
                    digest TEXT NOT NULL, PRIMARY KEY(node, epoch, sequence));
                CREATE TABLE IF NOT EXISTS counters (
                    node TEXT NOT NULL, epoch TEXT NOT NULL, subject TEXT NOT NULL,
                    upload INTEGER NOT NULL, download INTEGER NOT NULL,
                    sequence INTEGER NOT NULL, PRIMARY KEY(node, epoch, subject));
                CREATE TABLE IF NOT EXISTS epochs (
                    node TEXT NOT NULL, epoch TEXT NOT NULL, generation INTEGER NOT NULL,
                    PRIMARY KEY(node, epoch), UNIQUE(node, generation));
            """)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, *, node: str, epoch: str, generation: int, sequence: int,
               counters: dict[str, dict[str, int]]) -> dict[str, Any]:
        if any(not isinstance(value, str) or not value or len(value) > 128
               for value in (node, epoch)):
            raise CounterRejected("invalid node or trusted epoch")
        if any(type(value) is not int or not 1 <= value <= 2**63 - 1
               for value in (generation, sequence)):
            raise CounterRejected("invalid generation or sequence")
        if not isinstance(counters, dict) or not counters or len(counters) > 10000:
            raise CounterRejected("empty or oversized counter batch")
        for subject, values in counters.items():
            if not isinstance(subject, str) or not subject or len(subject) > 128:
                raise CounterRejected("invalid subject")
            if not isinstance(values, dict) or set(values) != {"upload", "download"}:
                raise CounterRejected("both directions required")
            if any(type(value) is not int or not 0 <= value <= 2**63 - 1
                   for value in values.values()):
                raise CounterRejected("invalid absolute byte counter")
        digest = hashlib.sha256(json.dumps(counters, sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            known = db.execute("SELECT generation FROM epochs WHERE node=? AND epoch=?",
                               (node, epoch)).fetchone()
            if known and known[0] != generation:
                raise CounterRejected("generation conflict")
            old = db.execute("SELECT digest FROM batches WHERE node=? AND epoch=? AND sequence=?",
                             (node, epoch, sequence)).fetchone()
            if old:
                if old[0] != digest:
                    raise CounterRejected("duplicate sequence content conflict")
                return {"applied": False, "duplicate": True, "delta": 0}
            latest = db.execute("SELECT epoch, generation FROM epochs WHERE node=? "
                                "ORDER BY generation DESC LIMIT 1", (node,)).fetchone()
            if known and (known[0] != generation or latest[0] != epoch):
                raise CounterRejected("retired epoch or generation conflict")
            if not known:
                if latest and generation <= latest[1]:
                    raise CounterRejected("epoch generation must advance")
                db.execute("INSERT INTO epochs VALUES (?, ?, ?)", (node, epoch, generation))
            previous_sequence = db.execute("SELECT MAX(sequence) FROM batches WHERE node=? AND epoch=?",
                                           (node, epoch)).fetchone()[0]
            if previous_sequence is not None and sequence <= previous_sequence:
                raise CounterRejected("out of order batch")
            delta = 0
            for subject, values in counters.items():
                old_counter = db.execute("SELECT upload, download FROM counters "
                                         "WHERE node=? AND epoch=? AND subject=?",
                                         (node, epoch, subject)).fetchone() or (0, 0)
                up, down = values["upload"], values["download"]
                if up < old_counter[0] or down < old_counter[1]:
                    raise CounterRejected("counter rollback requires reviewed new epoch")
                delta += up - old_counter[0] + down - old_counter[1]
                db.execute("INSERT OR REPLACE INTO counters VALUES (?, ?, ?, ?, ?, ?)",
                           (node, epoch, subject, up, down, sequence))
            db.execute("INSERT INTO batches VALUES (?, ?, ?, ?)", (node, epoch, sequence, digest))
            # Older replays are rejected by sequence, not counted anew. Keep only
            # a bounded recent digest window; checkpoints retain absolute totals.
            db.execute("DELETE FROM batches WHERE node=? AND epoch=? AND sequence NOT IN "
                       "(SELECT sequence FROM batches WHERE node=? AND epoch=? "
                       "ORDER BY sequence DESC LIMIT 1024)", (node, epoch, node, epoch))
        return {"applied": True, "duplicate": False, "delta": delta,
                "continuity": "restart_gap_possible" if latest and not known else "within_epoch"}

    def totals(self, subject: str) -> dict[str, Any]:
        with self._connect() as db:
            rows = db.execute("SELECT node, epoch, upload, download FROM counters WHERE subject=?",
                              (subject,)).fetchall()
        # Distinct active nodes contribute independently. Replica import must retain
        # the original node/epoch keys, never rename a replica into another writer.
        up = sum(row[2] for row in rows)
        down = sum(row[3] for row in rows)
        return {"upload": up if rows else None, "download": down if rows else None,
                "total": up + down if rows else None, "available": bool(rows),
                "components": [{"node": row[0], "epoch": row[1], "upload": row[2],
                                "download": row[3]} for row in rows]}

    def verify_restore(self, expected: dict[tuple[str, str, str], tuple[int, int]]) -> None:
        """Reject rollback against an independently retained checkpoint."""
        with self._connect() as db:
            for key, minimum in expected.items():
                actual = db.execute("SELECT upload, download FROM counters "
                                    "WHERE node=? AND epoch=? AND subject=?", key).fetchone()
                if actual is None or any(value < floor for value, floor in zip(actual, minimum)):
                    raise CounterRejected("restored database below external checkpoint")
