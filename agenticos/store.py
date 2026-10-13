"""Durable kernel state (SQLite) and the hash-chained audit log.

The kernel is a single asyncio thread, so one connection is enough; every mutating
helper commits immediately so a kernel crash never loses an acknowledged transition.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS intents (
  intent_id TEXT PRIMARY KEY, tenant TEXT, body TEXT, body_hash TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY, agent_type TEXT, tenant TEXT, owner TEXT, role TEXT,
  intent_id TEXT, delegation_id TEXT, parent_agent TEXT, priority TEXT, deadline REAL,
  state TEXT, wait_reason TEXT, restarts INTEGER DEFAULT 0, retry_budget INTEGER,
  params TEXT, result TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS agent_history (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, from_state TEXT, to_state TEXT,
  reason TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS delegations (
  delegation_id TEXT PRIMARY KEY, parent_id TEXT, root_intent_id TEXT, delegator TEXT,
  delegatee TEXT, tenant TEXT, capabilities TEXT, targets TEXT, memory_paths TEXT,
  production_write INTEGER, budget_calls INTEGER, budget_tokens INTEGER,
  used_calls INTEGER DEFAULT 0, used_tokens INTEGER DEFAULT 0,
  reserved_calls INTEGER DEFAULT 0, reserved_tokens INTEGER DEFAULT 0,
  valid_until REAL, revoked INTEGER DEFAULT 0, settled INTEGER DEFAULT 0, created_at REAL);
CREATE TABLE IF NOT EXISTS checkpoints (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, data TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS idempotency (
  key TEXT PRIMARY KEY, agent_id TEXT, op TEXT, target TEXT, status TEXT, result TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY, path TEXT, tenant TEXT, version INTEGER, data TEXT,
  provenance TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS messages (
  message_id TEXT PRIMARY KEY, source TEXT, destination TEXT, type TEXT, correlation_id TEXT,
  payload TEXT, evidence_refs TEXT, deadline REAL, status TEXT, ts REAL, client_id TEXT,
  UNIQUE(source, client_id));
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY, agent_id TEXT, intent_id TEXT, op TEXT, target TEXT,
  args_hash TEXT, expected_state TEXT, confidence_ref TEXT, package TEXT, status TEXT,
  approver TEXT, expires_at REAL, ts REAL);
CREATE TABLE IF NOT EXISTS confidence (
  confidence_id TEXT PRIMARY KEY, agent_id TEXT, intent_id TEXT, body TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, event TEXT, agent_id TEXT, intent_id TEXT,
  delegation_id TEXT, data TEXT, prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER);
"""

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256(obj: Any) -> str:
    data = obj if isinstance(obj, str) else canonical(obj)
    return hashlib.sha256(data.encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    # -- generic helpers -------------------------------------------------
    def exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        cur = self.db.execute(sql, params)
        self.db.commit()
        return cur

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.db.execute(sql, params).fetchone()

    def all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self.db.execute(sql, params).fetchall()

    def next_id(self, prefix: str) -> str:
        row = self.one("SELECT value FROM counters WHERE name=?", (prefix,))
        value = (row["value"] if row else 0) + 1
        self.exec("INSERT OR REPLACE INTO counters(name, value) VALUES (?, ?)", (prefix, value))
        return f"{prefix}-{value:04d}"

    # -- audit: append-only, hash-chained (AOS-0001 A.6, INV-007) ----------
    def audit(self, event: str, *, agent_id: str | None = None, intent_id: str | None = None,
              delegation_id: str | None = None, **data: Any) -> str:
        last = self.one("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
        prev = last["hash"] if last else GENESIS
        ts = time.time()
        record = {"ts": ts, "event": event, "agent_id": agent_id, "intent_id": intent_id,
                  "delegation_id": delegation_id, "data": data, "prev_hash": prev}
        digest = sha256(record)
        self.exec(
            "INSERT INTO audit(ts, event, agent_id, intent_id, delegation_id, data, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ts, event, agent_id, intent_id, delegation_id, canonical(data), prev, digest))
        return digest

    def verify_audit(self) -> tuple[bool, int, str]:
        """Recompute the chain. Returns (ok, records_checked, message)."""
        prev = GENESIS
        rows = self.all("SELECT * FROM audit ORDER BY seq")
        for row in rows:
            record = {"ts": row["ts"], "event": row["event"], "agent_id": row["agent_id"],
                      "intent_id": row["intent_id"], "delegation_id": row["delegation_id"],
                      "data": json.loads(row["data"]), "prev_hash": row["prev_hash"]}
            if row["prev_hash"] != prev or sha256(record) != row["hash"]:
                return False, row["seq"], f"chain broken at seq {row['seq']} ({row['event']})"
            prev = row["hash"]
        return True, len(rows), "audit chain intact"
