"""SQLite store for trusted-SSID baselines."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from twinwatch.baseline import Baseline


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "twinwatch"


def default_db() -> Path:
    return data_dir() / "twinwatch.db"


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS baselines ("
            " ssid TEXT PRIMARY KEY, created REAL NOT NULL, data TEXT NOT NULL)"
        )

    def save(self, baseline: Baseline) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO baselines (ssid, created, data) VALUES (?, ?, ?)",
                (baseline.ssid, baseline.created, json.dumps(baseline.to_dict())),
            )

    def load(self, ssid: str) -> Baseline | None:
        row = self._db.execute("SELECT data FROM baselines WHERE ssid = ?", (ssid,)).fetchone()
        return Baseline.from_dict(json.loads(row[0])) if row else None

    def ssids(self) -> list[str]:
        return [r[0] for r in self._db.execute("SELECT ssid FROM baselines ORDER BY ssid")]

    def close(self) -> None:
        self._db.close()
