"""Terminal tables, desktop alerts and the alert log."""

from __future__ import annotations

import shutil
import subprocess
import time
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from rich.table import Table

from twinwatch.baseline import Baseline
from twinwatch.detectors import LEVEL_RANK, LIKELY, SAFE, SUSPICIOUS, Verdict
from twinwatch.model import APRecord

LEVEL_STYLE = {SAFE: "green", SUSPICIOUS: "yellow", LIKELY: "bold red"}


def _opt(value) -> str:
    return "-" if value is None else str(value)


def ap_table(aps: Iterable[APRecord], title: str | None = None) -> Table:
    table = Table(title=title)
    for col in ("SSID", "BSSID", "Ch", "Band", "dBm", "Security", "AKM", "Beacon TU", "Capab", "Label"):
        table.add_column(col)
    for ap in sorted(aps, key=lambda a: (a.ssid, -(a.signal_dbm or -999))):
        table.add_row(
            ap.ssid or "<hidden>",
            ap.bssid,
            str(ap.channel),
            ap.band,
            _opt(ap.signal_dbm),
            "/".join(ap.security),
            "/".join(ap.akm) or "-",
            _opt(ap.beacon_interval),
            "-" if ap.capabilities is None else f"0x{ap.capabilities:04x}",
            _opt(ap.label),
        )
    return table


def baseline_table(baseline: Baseline) -> Table:
    table = Table(title=f"Baseline for {baseline.ssid!r}: {len(baseline.aps)} APs, "
                        f"{baseline.scans} scans")
    for col in ("BSSID", "Freqs MHz", "Security", "AKM", "Beacon TU", "Capab", "Median dBm", "Seen"):
        table.add_column(col)
    for ap in baseline.aps:
        table.add_row(
            ap.bssid,
            ",".join(map(str, ap.freqs)),
            "/".join(ap.security),
            "/".join(ap.akm) or "-",
            _opt(ap.beacon_interval),
            "-" if ap.capabilities is None else f"0x{ap.capabilities:04x}",
            _opt(ap.rssi_median),
            f"{ap.seen}/{baseline.scans}",
        )
    return table


def verdict_table(verdicts: list[Verdict], title: str) -> Table:
    table = Table(title=title)
    for col in ("Risk", "Score", "BSSID", "Ch", "dBm", "Security", "Signals"):
        table.add_column(col)
    for v in verdicts:
        table.add_row(
            f"[{LEVEL_STYLE[v.level]}]{v.level}[/]",
            f"{v.score:.2f}",
            v.ap.bssid,
            str(v.ap.channel),
            _opt(v.ap.signal_dbm),
            "/".join(v.ap.security),
            ", ".join(v.reasons) or "-",
        )
    return table


def outcome_table(outcomes: Counter[tuple[str, str]], title: str) -> Table:
    """Counts of verdicts per (label, risk level)."""
    levels = sorted(LEVEL_RANK, key=LEVEL_RANK.get)
    table = Table(title=title)
    table.add_column("Label")
    for level in levels:
        table.add_column(level, justify="right")
    for label in sorted({lab for lab, _ in outcomes}):
        table.add_row(label, *(str(outcomes[(label, lv)]) for lv in levels))
    return table


class Alerter:
    """Raises an alert when an AP first reaches Suspicious or its risk level rises.

    APs are keyed by BSSID and frequency, so a cloned BSSID on another channel
    alerts separately from the real AP.
    """

    def __init__(self, log_path: Path, desktop: bool = True):
        self.log_path = log_path
        self.desktop = desktop and shutil.which("notify-send") is not None
        self._levels: dict[tuple[str, int], int] = {}

    def update(self, verdicts: list[Verdict]) -> list[Verdict]:
        raised = []
        for v in verdicts:
            key = (v.ap.bssid, v.ap.freq_mhz)
            rank = LEVEL_RANK[v.level]
            if rank > self._levels.get(key, LEVEL_RANK[SAFE]):
                raised.append(v)
            self._levels[key] = rank
        for v in raised:
            self._log(v)
            if self.desktop:
                self._notify(v)
        return raised

    def _log(self, v: Verdict) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(f"{stamp} {v.level} score={v.score:.2f} ssid={v.ap.ssid!r} "
                    f"bssid={v.ap.bssid} freq={v.ap.freq_mhz} signals={','.join(v.reasons)}\n")

    def _notify(self, v: Verdict) -> None:
        urgency = "critical" if v.level == LIKELY else "normal"
        subprocess.run(
            ["notify-send", "-u", urgency, f"TwinWatch: {v.level}",
             f"{v.ap.ssid} {v.ap.bssid} ch {v.ap.channel}\n{', '.join(v.reasons)}"],
            check=False, timeout=5,
        )
