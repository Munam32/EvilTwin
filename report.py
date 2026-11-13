"""Terminal output. Risk tables, desktop alerts and the log come in a later part."""

from __future__ import annotations

from collections.abc import Iterable

from rich.table import Table

from model import APRecord


def _opt(value) -> str:
    return "-" if value is None else str(value)


def ap_table(aps: Iterable[APRecord], title: str | None = None) -> Table:
    table = Table(title=title)
    for col in ("SSID", "BSSID", "Ch", "Band", "dBm", "Security", "AKM", "Beacon TU", "Label"):
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
            _opt(ap.label),
        )
    return table
