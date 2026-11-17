"""Per-beacon handling shared by monitor-mode capture and the AWID3 converter.

Both see individual beacon and probe-response frames rather than scan
results: suites arrive as IEEE 802.11 numeric codes, and the frames of one AP
within a time window are merged into one APRecord.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Iterable, Iterator

from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot, derive_security

# IEEE 802.11 AKM suite selectors (00-0F-AC:n).
AKM_NAMES = {1: "EAP", 2: "PSK", 3: "EAP", 4: "PSK", 5: "EAP", 6: "PSK", 8: "SAE", 9: "SAE",
             11: "EAP-SUITE-B", 12: "EAP-SUITE-B", 13: "EAP", 18: "OWE", 24: "SAE", 25: "SAE"}
CIPHER_NAMES = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP-128",
                9: "GCMP-256", 10: "CCMP-256"}


def security_from_suites(rsn_akm: list[int] | None, wpa_akm: list[int] | None,
                         pairwise: Iterable[int], privacy: bool
                         ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """(security, akm, pairwise) from suite codes. None means the element is absent."""
    rsn_names = {AKM_NAMES[c] for c in rsn_akm or () if c in AKM_NAMES}
    wpa_names = {AKM_NAMES[c] for c in wpa_akm or () if c in AKM_NAMES}
    security = derive_security(wpa_akm is not None, rsn_akm is not None, rsn_names, privacy)
    ciphers = {CIPHER_NAMES[c] for c in pairwise if c in CIPHER_NAMES}
    return security, tuple(sorted(rsn_names | wpa_names)), tuple(sorted(ciphers))


def _mode(values: Iterable):
    values = [v for v in values if v is not None]
    return Counter(values).most_common(1)[0][0] if values else None


def tsf_backwards(frames: list[APRecord]) -> int | None:
    """How often the TSF decreased from one frame to the next, in capture order.

    One device's TSF only counts up (until it reboots), so a decrease means a
    second device is beaconing with the same BSSID on the same channel.
    """
    tsfs = [f.tsf for f in frames]
    if not tsfs or None in tsfs:
        return None
    return sum(b < a for a, b in zip(tsfs, tsfs[1:]))


def merge(frames: list[APRecord]) -> APRecord:
    """All frames of one AP (BSSID + frequency) in one window, in capture order -> one record."""
    signals = [f.signal_dbm for f in frames if f.signal_dbm is not None]
    labels = {f.label for f in frames}
    last = frames[-1]
    return APRecord(
        bssid=last.bssid,
        ssid=_mode(f.ssid for f in frames),
        freq_mhz=last.freq_mhz,
        signal_dbm=statistics.median(signals) if signals else None,
        security=_mode(f.security for f in frames),
        akm=_mode(f.akm for f in frames),
        pairwise=_mode(f.pairwise for f in frames),
        beacon_interval=_mode(f.beacon_interval for f in frames),
        capabilities=_mode(f.capabilities for f in frames),
        tsf=last.tsf,
        tsf_backwards=tsf_backwards(frames),
        label=EVIL_TWIN if EVIL_TWIN in labels else BENIGN if BENIGN in labels else None,
    )


def merge_window(frames: Iterable[APRecord]) -> tuple[APRecord, ...]:
    """Frames of many APs in capture order -> one merged record per (BSSID, frequency)."""
    groups: dict[tuple[str, int], list[APRecord]] = {}
    for frame in frames:
        groups.setdefault((frame.bssid, frame.freq_mhz), []).append(frame)
    return tuple(merge(g) for _, g in sorted(groups.items()))


def windowed(frames: Iterable[tuple[float, APRecord]], window_s: float, source: str,
             meta: dict) -> Iterator[Snapshot]:
    """(time, frame) pairs in capture order -> one Snapshot per `window_s` seconds.

    Each window is one scan cycle of the live tool; empty windows are skipped.
    """
    start: float | None = None
    current: list[APRecord] = []
    for t, record in frames:
        if start is None:
            start = t
        if t >= start + window_s:
            if current:
                yield Snapshot(time=start, source=source, aps=merge_window(current), meta=meta)
                current = []
            start += window_s * ((t - start) // window_s)
        current.append(record)
    if current:
        yield Snapshot(time=start, source=source, aps=merge_window(current), meta=meta)

