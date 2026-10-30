"""SQLite-backed store.

Design (AR-8): every write is first appended to an immutable `events`
journal (event-sourced audit trail), then projected into a current-state
document table. Documents are stored as JSON; the journal is append-only
and never updated or deleted by application code.

In production this maps to an append-only event store + projections; the
interface is what the rest of the platform depends on.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    kind       TEXT NOT NULL,      -- e.g. spec.ingested, finding.transition
    entity     TEXT NOT NULL,      -- collection name
    entity_id  TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT 'system',
    payload    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
    collection TEXT NOT NULL,
    id         TEXT NOT NULL,
    body       TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (collection, id)
);
CREATE INDEX IF NOT EXISTS idx_events_entity ON events (entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ── event journal (append-only) ────────────────────────────────────

    def append_event(
        self,
        kind: str,
        entity: str,
        entity_id: str,
        payload: dict[str, Any],
        actor: str = "system",
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, kind, entity, entity_id, actor, payload)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (_now(), kind, entity, entity_id, actor, json.dumps(payload)),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def events(
        self,
        kind: Optional[str] = None,
        entity: Optional[str] = None,
        entity_id: Optional[str] = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        q = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if kind:
            q += " AND kind = ?"
            params.append(kind)
        if entity:
            q += " AND entity = ?"
            params.append(entity)
        if entity_id:
            q += " AND entity_id = ?"
            params.append(entity_id)
        q += " ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        return [
            {
                "seq": r["seq"],
                "ts": r["ts"],
                "kind": r["kind"],
                "entity": r["entity"],
                "entity_id": r["entity_id"],
                "actor": r["actor"],
                "payload": json.loads(r["payload"]),
            }
            for r in rows
        ]

    # ── document projections ───────────────────────────────────────────

    def put(self, collection: str, doc_id: str, body: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO documents (collection, id, body, updated_at)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT (collection, id) DO UPDATE SET body=excluded.body,"
                " updated_at=excluded.updated_at",
                (collection, doc_id, json.dumps(body), _now()),
            )
            self._conn.commit()

    def get(self, collection: str, doc_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM documents WHERE collection = ? AND id = ?",
                (collection, doc_id),
            ).fetchone()
        return json.loads(row["body"]) if row else None

    def all(self, collection: str) -> Iterator[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT body FROM documents WHERE collection = ? ORDER BY updated_at",
                (collection,),
            ).fetchall()
        for r in rows:
            yield json.loads(r["body"])

    def delete(self, collection: str, doc_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM documents WHERE collection = ? AND id = ?",
                (collection, doc_id),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
