"""Snapshot recordings: JSON Lines, one snapshot per line, append-only."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path

from twinwatch.model import Snapshot


def append(path: Path, snapshot: Snapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot.to_dict()) + "\n")


def sessions(snapshots: Iterable[Snapshot], default: str) -> dict[tuple[str, str], list[Snapshot]]:
    """Group snapshots into sessions keyed by (session id, trusted SSID), in order.

    The session id is `meta["session"]` (synthetic data) or `default`, usually
    the file name. One file can hold several SSIDs, e.g. a 2.4 GHz and a 5 GHz
    network recorded one after the other.
    """
    groups: dict[tuple[str, str], list[Snapshot]] = {}
    for snap in snapshots:
        key = (snap.meta.get("session", default), snap.meta.get("ssid", ""))
        groups.setdefault(key, []).append(snap)
    return groups


def read(path: Path) -> Iterator[Snapshot]:
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                yield Snapshot.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError) as e:
                raise ValueError(f"{path}:{line_no}: bad snapshot: {e}") from e
