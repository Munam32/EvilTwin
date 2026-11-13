"""Snapshot recordings: JSON Lines, one snapshot per line, append-only."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from model import Snapshot


def append(path: Path, snapshot: Snapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot.to_dict()) + "\n")


def read(path: Path) -> Iterator[Snapshot]:
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                yield Snapshot.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError) as e:
                raise ValueError(f"{path}:{line_no}: bad snapshot: {e}") from e
