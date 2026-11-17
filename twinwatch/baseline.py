"""Baseline fingerprint of a trusted SSID, learned from scans (trust on first use)."""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from twinwatch.lookalike import related
from twinwatch.model import SECURITY_RANK, APRecord, Snapshot


@dataclass(frozen=True)
class BaselineAP:
    bssid: str
    freqs: tuple[int, ...]
    security: tuple[str, ...]
    akm: tuple[str, ...]
    beacon_interval: int | None
    capabilities: int | None
    rssi_median: float | None
    rssi_spread: float | None  # median absolute deviation
    seen: int

    @property
    def security_rank(self) -> int:
        return max(SECURITY_RANK[s] for s in self.security)


@dataclass(frozen=True)
class Baseline:
    ssid: str
    created: float
    scans: int
    aps: tuple[BaselineAP, ...]
    # BSSIDs with a lookalike or sibling SSID seen while learning: trusted neighbours, not twins.
    neighbours: tuple[str, ...] = ()

    def candidates(self, snapshot: Snapshot) -> list[APRecord]:
        """APs to check: every AP of the trusted SSID, and new APs with a lookalike or sibling SSID."""
        return [ap for ap in snapshot.aps
                if ap.ssid == self.ssid or (ap.bssid not in self.neighbours and related(ap.ssid, self.ssid))]

    def get(self, bssid: str) -> BaselineAP | None:
        return next((ap for ap in self.aps if ap.bssid == bssid), None)

    @property
    def ouis(self) -> set[str]:
        return {ap.bssid[:8] for ap in self.aps}

    @property
    def freqs(self) -> set[int]:
        return {f for ap in self.aps for f in ap.freqs}

    @property
    def security_profiles(self) -> set[tuple[tuple[str, ...], tuple[str, ...]]]:
        return {(ap.security, ap.akm) for ap in self.aps}

    @property
    def min_security_rank(self) -> int:
        return min(ap.security_rank for ap in self.aps)

    @property
    def beacon_intervals(self) -> set[int]:
        return {ap.beacon_interval for ap in self.aps if ap.beacon_interval is not None}

    @property
    def capabilities(self) -> set[int]:
        return {ap.capabilities for ap in self.aps if ap.capabilities is not None}

    @property
    def strongest_rssi(self) -> float | None:
        values = [ap.rssi_median for ap in self.aps if ap.rssi_median is not None]
        return max(values) if values else None

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid,
            "created": self.created,
            "scans": self.scans,
            "aps": [vars(ap) for ap in self.aps],
            "neighbours": list(self.neighbours),
        }

    @classmethod
    def from_dict(cls, d: dict) -> Baseline:
        aps = tuple(
            BaselineAP(**{**a, "freqs": tuple(a["freqs"]), "security": tuple(a["security"]),
                          "akm": tuple(a["akm"])})
            for a in d["aps"]
        )
        return cls(ssid=d["ssid"], created=d["created"], scans=d["scans"], aps=aps,
                   neighbours=tuple(d.get("neighbours", ())))


def _mode(values: Iterable):
    values = [v for v in values if v is not None]
    return Counter(values).most_common(1)[0][0] if values else None


def _fingerprint(bssid: str, records: list[APRecord]) -> BaselineAP:
    rssi = [r.signal_dbm for r in records if r.signal_dbm is not None]
    median = statistics.median(rssi) if rssi else None
    return BaselineAP(
        bssid=bssid,
        freqs=tuple(sorted({r.freq_mhz for r in records})),
        security=_mode(r.security for r in records),
        akm=_mode(r.akm for r in records),
        beacon_interval=_mode(r.beacon_interval for r in records),
        capabilities=_mode(r.capabilities for r in records),
        rssi_median=median,
        rssi_spread=statistics.median(abs(v - median) for v in rssi) if rssi else None,
        seen=len(records),
    )


def build(snapshots: Iterable[Snapshot], ssid: str) -> Baseline:
    """Fingerprint every AP broadcasting `ssid` across the given scans."""
    by_bssid: dict[str, list[APRecord]] = {}
    neighbours: set[str] = set()
    scans, created = 0, None
    for snap in snapshots:
        scans += 1
        created = created if created is not None else snap.time
        for ap in snap.aps:
            if ap.ssid == ssid:
                by_bssid.setdefault(ap.bssid, []).append(ap)
            elif related(ap.ssid, ssid):
                neighbours.add(ap.bssid)
    if not by_bssid:
        raise ValueError(f"no AP broadcasting {ssid!r} in {scans} scans")
    aps = tuple(_fingerprint(b, recs) for b, recs in sorted(by_bssid.items()))
    return Baseline(ssid=ssid, created=created, scans=scans, aps=aps,
                    neighbours=tuple(sorted(neighbours - by_bssid.keys())))
