"""SQLite storage for driftcanary.

Tables:
  schema_version — single-row migration marker.
  runs           — one row per probe execution.
  results        — one row per (run, probe, metric) numeric observation.
  config         — key/value runtime settings.

No network access at rest. The database lives at <data_dir>/driftcanary.db.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,          -- 'provider' or 'agent'
    target_name TEXT NOT NULL,         -- model id or CLI name
    started_at TEXT NOT NULL,         -- ISO-8601 UTC
    finished_at TEXT,
    status     TEXT NOT NULL           -- 'ok' | 'partial' | 'error'
);
CREATE TABLE IF NOT EXISTS results (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    probe   TEXT NOT NULL,
    metric  TEXT NOT NULL,
    value   REAL NOT NULL,
    samples INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_results_series
    ON results (probe, metric, run_id);
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


class Store:
    """Thin SQLite wrapper. All timestamps are UTC ISO-8601 strings."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = os.path.abspath(os.path.expanduser(data_dir))
        os.makedirs(self.data_dir, exist_ok=True)
        self.path = os.path.join(self.data_dir, "driftcanary.db")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (SCHEMA_VERSION,),
                )
            elif row["version"] != SCHEMA_VERSION:
                raise RuntimeError(
                    "driftcanary.db schema v%s is newer than this client "
                    "(v%s); upgrade driftcanary first."
                    % (row["version"], SCHEMA_VERSION)
                )

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = _connect(self.path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- runs -----------------------------------------------------------

    def start_run(self, target: str, target_name: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO runs (target, target_name, started_at, status)"
                " VALUES (?, ?, ?, 'error')",
                (target, target_name, now),
            )
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                "UPDATE runs SET finished_at = ?, status = ? WHERE id = ?",
                (now, status, run_id),
            )

    def record(self, run_id: int, probe: str, metric: str,
               value: float, samples: int = 1) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO results (run_id, probe, metric, value, samples)"
                " VALUES (?, ?, ?, ?, ?)",
                (run_id, probe, metric, float(value), int(samples)),
            )

    # -- reads ----------------------------------------------------------

    def list_targets(self) -> List[Tuple[str, str]]:
        """Distinct (target, target_name) pairs that have at least one run."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT target, target_name FROM runs ORDER BY 1, 2"
            ).fetchall()
        return [(r["target"], r["target_name"]) for r in rows]

    def run_count(self, target: str, target_name: str,
                  status: str = "ok") -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM runs"
                " WHERE target = ? AND target_name = ? AND status = ?",
                (target, target_name, status),
            ).fetchone()
        return int(row["n"])

    def last_run_at(self, target: str, target_name: str) -> Optional[str]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT started_at FROM runs"
                " WHERE target = ? AND target_name = ?"
                " ORDER BY id DESC LIMIT 1",
                (target, target_name),
            ).fetchone()
        return row["started_at"] if row else None

    def series(self, target: str, target_name: str,
               probe: str, metric: str,
               limit: Optional[int] = None) -> List[Tuple[int, float]]:
        """Ordered (run_id, value) observations for one probe metric.

        Only completed 'ok'/'partial' runs are included; errored runs never
        contribute to the baseline.
        """
        q = (
            "SELECT r.run_id AS run_id, r.value AS value"
            " FROM results r JOIN runs u ON u.id = r.run_id"
            " WHERE u.target = ? AND u.target_name = ?"
            "   AND r.probe = ? AND r.metric = ?"
            "   AND u.status IN ('ok', 'partial')"
            " ORDER BY r.run_id ASC"
        )
        params: Tuple[Any, ...] = (target, target_name, probe, metric)
        if limit is not None:
            q += " LIMIT ?"
            params += (int(limit),)
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        return [(int(r["run_id"]), float(r["value"])) for r in rows]

    def probe_metrics(self, target: str, target_name: str) -> List[Tuple[str, str]]:
        """Distinct (probe, metric) pairs observed for a target."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT r.probe AS probe, r.metric AS metric"
                " FROM results r JOIN runs u ON u.id = r.run_id"
                " WHERE u.target = ? AND u.target_name = ?"
                " ORDER BY 1, 2",
                (target, target_name),
            ).fetchall()
        return [(r["probe"], r["metric"]) for r in rows]

    # -- config ---------------------------------------------------------

    def get_config(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM config WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_config(self, key: str, value: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO config (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def as_dict(self) -> Dict[str, Any]:
        """Whole-database export for the HTML report (small by design)."""
        out: Dict[str, Any] = {"targets": []}
        for target, target_name in self.list_targets():
            entry: Dict[str, Any] = {
                "target": target,
                "target_name": target_name,
                "run_count": self.run_count(target, target_name),
                "last_run_at": self.last_run_at(target, target_name),
                "series": {},
            }
            for probe, metric in self.probe_metrics(target, target_name):
                entry["series"]["%s.%s" % (probe, metric)] = self.series(
                    target, target_name, probe, metric
                )
            out["targets"].append(entry)
        return out
