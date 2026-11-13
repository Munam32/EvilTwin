"""Parser for `iw dev <if> scan [dump]` output.

iw gives the richest managed-mode view: signal in dBm, beacon interval,
capability bits, the AP's TSF and full RSN/WPA suites.
"""

from __future__ import annotations

import re

from twinwatch.model import APRecord, derive_security

_BSS = re.compile(r"^BSS ([0-9a-fA-F:]{17})", re.M)
_FREQ = re.compile(r"^\s*freq: ([\d.]+)", re.M)
_SIGNAL = re.compile(r"^\s*signal: (-?[\d.]+) dBm", re.M)
_SSID = re.compile(r"^\s*SSID: ?(.*)$", re.M)
_BEACON = re.compile(r"^\s*beacon interval: (\d+) TUs", re.M)
_CAPAB = re.compile(r"^\s*capability:.*\((0x[0-9a-fA-F]+)\)", re.M)
_TSF = re.compile(r"^\s*TSF: (\d+) usec", re.M)
_LAST_SEEN = re.compile(r"^\s*last seen: (\d+) ms ago", re.M)
_HEX_ESCAPE = re.compile(rb"\\x([0-9a-fA-F]{2})")

PRIVACY_BIT = 0x0010


def _ie_block(block: str, name: str) -> str | None:
    """Text of an RSN/WPA element: its header line plus the indented `*` lines."""
    m = re.search(rf"^\s*{name}:(.*(?:\n\s+\*.*)*)", block, re.M)
    return m.group(1) if m else None


def _ie_field(ie: str, name: str) -> list[str]:
    m = re.search(rf"\* {name}: (.*)", ie)
    if not m:
        return []
    # "IEEE 802.1X" is one suite name containing a space.
    return m.group(1).replace("IEEE 802.1X", "IEEE_802.1X").split()


def _normalize_akm(suite: str) -> str:
    s = suite.upper()
    if "SAE" in s:
        return "SAE"
    if "OWE" in s:
        return "OWE"
    if "SUITE-B" in s:
        return "EAP-SUITE-B"
    if "802.1X" in s:
        return "EAP"
    return "PSK"


def _decode_ssid(raw: str) -> str:
    data = _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), raw.encode())
    return data.decode("utf-8", errors="replace")


def _parse_block(block: str) -> APRecord | None:
    bssid = _BSS.search(block)
    freq = _FREQ.search(block)
    if not bssid or not freq:
        return None
    ssid = _SSID.search(block)
    signal = _SIGNAL.search(block)
    beacon = _BEACON.search(block)
    capab = _CAPAB.search(block)
    tsf = _TSF.search(block)
    capabilities = int(capab.group(1), 16) if capab else None

    akm: set[str] = set()
    pairwise: set[str] = set()
    rsn_akm: set[str] = set()
    ies = {name: _ie_block(block, name) for name in ("RSN", "WPA")}
    for name, ie in ies.items():
        if ie is None:
            continue
        suites = {_normalize_akm(s) for s in _ie_field(ie, "Authentication suites")}
        akm |= suites
        if name == "RSN":
            rsn_akm = suites
        pairwise.update(_ie_field(ie, "Pairwise ciphers"))
    security = derive_security(
        wpa=ies["WPA"] is not None,
        rsn=ies["RSN"] is not None,
        rsn_akm=rsn_akm,
        privacy=bool(capabilities is not None and capabilities & PRIVACY_BIT),
    )

    return APRecord(
        bssid=bssid.group(1),
        ssid=_decode_ssid(ssid.group(1)) if ssid else "",
        freq_mhz=round(float(freq.group(1))),
        signal_dbm=float(signal.group(1)) if signal else None,
        security=security,
        akm=tuple(sorted(akm)),
        pairwise=tuple(sorted(pairwise)),
        beacon_interval=int(beacon.group(1)) if beacon else None,
        capabilities=capabilities,
        tsf=int(tsf.group(1)) if tsf else None,
    )


def parse(output: str, max_age_ms: int | None = None) -> list[APRecord]:
    """Parse iw scan output. Entries last seen more than max_age_ms ago are dropped."""
    starts = [m.start() for m in _BSS.finditer(output)] + [len(output)]
    records = []
    for begin, end in zip(starts, starts[1:]):
        block = output[begin:end]
        if max_age_ms is not None:
            seen = _LAST_SEEN.search(block)
            if seen and int(seen.group(1)) > max_age_ms:
                continue
        record = _parse_block(block)
        if record is not None:
            records.append(record)
    return records
