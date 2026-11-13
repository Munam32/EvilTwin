"""AWID3 beacon frames -> windowed Snapshots with evil twin labels.

Input is either an AWID3 CSV (one row per frame, tshark field names as column
headers, plus a `Label` column) or a pcap, which is read through tshark into
the same columns. Only beacons and probe responses are used: they carry the
fingerprint fields. Frames are grouped into fixed time windows, so each window
becomes one Snapshot, like one scan cycle of the live tool.

Usage:
    python -m twinwatch.datasets.awid3 INPUT.csv|INPUT.pcap -o OUT.jsonl [--window 10]
"""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import statistics
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path

from twinwatch import recording
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot, derive_security

csv.field_size_limit(sys.maxsize)

BEACON, PROBE_RESPONSE = 0x0008, 0x0005

TIME = "frame.time_epoch"
SUBTYPE = "wlan.fc.type_subtype"
BSSID = "wlan.bssid"
SSID = "wlan.ssid"
FREQS = ("radiotap.channel.freq", "wlan_radio.frequency")
SIGNALS = ("radiotap.dbm_antsignal", "wlan_radio.signal_dbm")
BEACON_INTERVAL = "wlan.fixed.beacon"
CAPABILITIES = "wlan.fixed.capabilities"
PRIVACY = "wlan.fixed.capabilities.privacy"
TSF = "wlan.fixed.timestamp"
RSN_AKM = "wlan.rsn.akms.type"
RSN_PAIRWISE = "wlan.rsn.pcs.type"
WPA_AKM = "wlan.wfa.ie.wpa.akms.type"
WPA_PAIRWISE = "wlan.wfa.ie.wpa.ucs.type"
LABEL = "Label"

TSHARK_FIELDS = (TIME, SUBTYPE, BSSID, SSID, *FREQS, *SIGNALS, BEACON_INTERVAL,
                 CAPABILITIES, PRIVACY, TSF, RSN_AKM, RSN_PAIRWISE, WPA_AKM, WPA_PAIRWISE)
REQUIRED = (TIME, SUBTYPE, BSSID, SSID)

# IEEE 802.11 AKM suite selectors (00-0F-AC:n).
AKM_NAMES = {1: "EAP", 2: "PSK", 3: "EAP", 4: "PSK", 5: "EAP", 6: "PSK", 8: "SAE", 9: "SAE",
             11: "EAP-SUITE-B", 12: "EAP-SUITE-B", 13: "EAP", 18: "OWE", 24: "SAE", 25: "SAE"}
CIPHER_NAMES = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP-128",
                9: "GCMP-256", 10: "CCMP-256"}

_HEX = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
_MULTI = re.compile(r"[,;]")


class AwidError(ValueError):
    pass


def _values(row: dict, key: str) -> list[str]:
    """All values of a field; tshark joins repeated fields with ',' or ';'."""
    raw = (row.get(key) or "").strip()
    return [v.strip() for v in _MULTI.split(raw) if v.strip()] if raw else []


def _first(row: dict, keys: Iterable[str]) -> str | None:
    for key in keys:
        values = _values(row, key)
        if values:
            return values[0]
    return None


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return int(float(value))


def _ints(row: dict, key: str) -> list[int]:
    return [_int(v) for v in _values(row, key)]


def _decode_ssid(raw: str) -> str:
    """tshark prints SSIDs as text, or as hex in some versions.

    Hex is decoded only when it yields printable UTF-8, so an SSID that is
    itself hex digits (e.g. 'cafe') stays as written.
    """
    if _HEX.match(raw):
        try:
            text = bytes.fromhex(raw).decode("utf-8")
        except UnicodeDecodeError:
            return raw
        if text.isprintable():
            return text
    return raw


def map_label(raw: str | None) -> str | None:
    """AWID3 label -> benign / evil_twin; other attack classes are left unlabelled."""
    if not raw:
        return None
    text = raw.strip().lower().replace("-", "_").replace(" ", "_")
    if text == "normal":
        return BENIGN
    if "evil" in text and "twin" in text:
        return EVIL_TWIN
    return None


def frame_to_record(row: dict) -> tuple[float, APRecord] | None:
    """One beacon or probe-response row -> (time, APRecord), or None for other frames."""
    subtype = _int(_first(row, (SUBTYPE,)))
    freq = _int(_first(row, FREQS))
    bssid = _first(row, (BSSID,))
    if subtype not in (BEACON, PROBE_RESPONSE) or freq is None or not bssid:
        return None

    rsn_codes, wpa_codes = _ints(row, RSN_AKM), _ints(row, WPA_AKM)
    rsn_akm = {AKM_NAMES[c] for c in rsn_codes if c in AKM_NAMES}
    wpa_akm = {AKM_NAMES[c] for c in wpa_codes if c in AKM_NAMES}
    capabilities = _int(_first(row, (CAPABILITIES,)))
    privacy_raw = (_first(row, (PRIVACY,)) or "").lower()
    privacy = privacy_raw in ("1", "true") or bool(capabilities and capabilities & 0x0010)
    rsn = bool(rsn_codes or _values(row, RSN_PAIRWISE))
    wpa = bool(wpa_codes or _values(row, WPA_PAIRWISE))
    pairwise = {CIPHER_NAMES[c] for c in _ints(row, RSN_PAIRWISE) + _ints(row, WPA_PAIRWISE)
                if c in CIPHER_NAMES}
    signal = _first(row, SIGNALS)

    record = APRecord(
        bssid=bssid,
        ssid=_decode_ssid(row.get(SSID) or ""),
        freq_mhz=freq,
        signal_dbm=float(signal) if signal is not None else None,
        security=derive_security(wpa, rsn, rsn_akm, privacy),
        akm=tuple(sorted(rsn_akm | wpa_akm)),
        pairwise=tuple(sorted(pairwise)),
        beacon_interval=_int(_first(row, (BEACON_INTERVAL,))),
        capabilities=capabilities,
        tsf=_int(_first(row, (TSF,))),
        label=map_label(row.get(LABEL)),
    )
    return float(row[TIME]), record


def _mode(values: Iterable):
    values = [v for v in values if v is not None]
    return Counter(values).most_common(1)[0][0] if values else None


def _merge(frames: list[APRecord]) -> APRecord:
    """All frames of one AP (BSSID + frequency) in one window -> one record."""
    signals = [f.signal_dbm for f in frames if f.signal_dbm is not None]
    labels = {f.label for f in frames}
    label = EVIL_TWIN if EVIL_TWIN in labels else BENIGN if BENIGN in labels else None
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
        label=label,
    )


def windows(rows: Iterable[dict], window_s: float, meta: dict) -> Iterator[Snapshot]:
    """Group frames into `window_s`-second Snapshots. Rows must be in capture order."""
    start: float | None = None
    current: dict[tuple[str, int], list[APRecord]] = {}

    def flush() -> Snapshot:
        aps = tuple(_merge(frames) for _, frames in sorted(current.items()))
        return Snapshot(time=start, source="awid3", aps=aps, meta=meta)

    for row in rows:
        parsed = frame_to_record(row)
        if parsed is None:
            continue
        t, record = parsed
        if start is None:
            start = t
        if t >= start + window_s:
            if current:
                yield flush()
                current = {}
            start += window_s * ((t - start) // window_s)
        current.setdefault((record.bssid, record.freq_mhz), []).append(record)
    if current:
        yield flush()


def read_csv(path: Path) -> Iterator[dict]:
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        check_columns(reader.fieldnames or [], path)
        yield from reader


def check_columns(columns: list[str], source: Path) -> None:
    missing = [c for c in REQUIRED if c not in columns]
    if not any(c in columns for c in FREQS):
        missing.append(" or ".join(FREQS))
    if missing:
        raise AwidError(f"{source} lacks columns: {', '.join(missing)}. "
                        "Convert the matching pcap instead.")


def read_pcap(path: Path) -> Iterator[dict]:
    if not shutil.which("tshark"):
        raise AwidError("reading pcaps needs tshark: sudo apt install tshark")
    cmd = ["tshark", "-r", str(path), "-n",
           "-Y", f"wlan.fc.type_subtype == {BEACON:#06x} || wlan.fc.type_subtype == {PROBE_RESPONSE:#06x}",
           "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d",
           "-E", "occurrence=a", "-E", "aggregator=;"]
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    yield from csv.DictReader(proc.stdout)
    proc.stdout.close()
    if proc.wait() != 0:
        raise AwidError(f"tshark failed on {path}: {proc.stderr.read().strip()}")


def convert(source: Path, out: Path, window_s: float = 10.0) -> Counter:
    """Convert one AWID3 file to a JSONL recording. Returns AP-window counts per label."""
    rows = read_pcap(source) if source.suffix in (".pcap", ".pcapng", ".cap") else read_csv(source)
    meta = {"dataset": "awid3", "file": source.name}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("")
    counts: Counter = Counter()
    for snap in windows(rows, window_s, meta):
        recording.append(out, snap)
        counts["snapshots"] += 1
        counts.update(ap.label or "unlabelled" for ap in snap.aps)
    return counts


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m twinwatch.datasets.awid3",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("input", type=Path, help="AWID3 .csv or .pcap/.pcapng")
    parser.add_argument("-o", "--out", type=Path, required=True, help="output .jsonl")
    parser.add_argument("--window", type=float, default=10.0, help="seconds per snapshot")
    args = parser.parse_args(argv)
    try:
        counts = convert(args.input, args.out, args.window)
    except (AwidError, OSError) as e:
        sys.exit(f"error: {e}")
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"{args.out}: {summary or 'no beacons found'}")


if __name__ == "__main__":
    main()
