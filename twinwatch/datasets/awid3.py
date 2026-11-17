"""AWID3 beacon frames -> windowed Snapshots with evil twin labels.

Input is either an AWID3 CSV (one row per frame, tshark field names as column
headers, plus a `Label` column) or a pcap, which is read through tshark into
the same columns. Only beacons and probe responses are used: they carry the
fingerprint fields.

The published AWID3 CSVs differ from a tshark export: frame type and subtype
are separate columns, the capability field is split into a few bits, and the
RSN AKM/cipher suites are missing. There, an RSN element is recognised by its
`wlan.rsn.capabilities.mfpc` field (security WPA2, AKM unknown) and
capabilities stay None. `radiotap.dbm_antsignal` holds several antennas
added together, so `wlan_radio.signal_dbm` is read first. Frames are grouped into fixed time windows, so each window
becomes one Snapshot, like one scan cycle of the live tool.

AWID3's own labels mark some of the twin's frames Normal; --evil-bssid labels
every frame of a known twin BSSID evil_twin instead. A twin that clones the
BSSID can only be told apart by its TSF (time since that device booted):
--evil-tsf-below SECONDS labels every frame with a lower TSF evil_twin. --ssid names the trusted
network in each snapshot's meta, which training and evaluation group by.

Usage:
    python -m twinwatch.datasets.awid3 INPUT.csv|INPUT.pcap -o OUT.jsonl [--window 10] \\
        [--ssid NAME] [--evil-bssid BSSID ...] [--evil-tsf-below SECONDS]
"""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path

from twinwatch import recording
from twinwatch.beacons import security_from_suites, windowed
from twinwatch.model import BENIGN, EVIL_TWIN, PRIVACY_BIT, APRecord, Snapshot

csv.field_size_limit(sys.maxsize)

BEACON, PROBE_RESPONSE = 0x0008, 0x0005

TIME = "frame.time_epoch"
SUBTYPE = "wlan.fc.type_subtype"
SUBTYPE_PARTS = ("wlan.fc.type", "wlan.fc.subtype")  # AWID3 CSV: type and subtype apart
BSSID = "wlan.bssid"
SSID = "wlan.ssid"
FREQS = ("radiotap.channel.freq", "wlan_radio.frequency")
SIGNALS = ("wlan_radio.signal_dbm", "radiotap.dbm_antsignal")
BEACON_INTERVAL = "wlan.fixed.beacon"
CAPABILITIES = "wlan.fixed.capabilities"
PRIVACY = "wlan.fixed.capabilities.privacy"
TSF = "wlan.fixed.timestamp"
RSN_AKM = "wlan.rsn.akms.type"
RSN_PAIRWISE = "wlan.rsn.pcs.type"
WPA_AKM = "wlan.wfa.ie.wpa.akms.type"
WPA_PAIRWISE = "wlan.wfa.ie.wpa.ucs.type"
RSN_MFPC = "wlan.rsn.capabilities.mfpc"  # present whenever the beacon has an RSN element
LABEL = "Label"

TSHARK_FIELDS = (TIME, SUBTYPE, BSSID, SSID, *FREQS, *SIGNALS, BEACON_INTERVAL,
                 CAPABILITIES, PRIVACY, TSF, RSN_AKM, RSN_PAIRWISE, WPA_AKM, WPA_PAIRWISE, RSN_MFPC)
REQUIRED = (TIME, BSSID, SSID)

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


def _subtype(row: dict) -> int | None:
    """Frame type/subtype code as in wlan.fc.type_subtype (beacon 0x0008)."""
    code = _int(_first(row, (SUBTYPE,)))
    if code is not None:
        return code
    kind, sub = (_int(_first(row, (key,))) for key in SUBTYPE_PARTS)
    return None if kind is None or sub is None else (kind << 4) | sub


def frame_to_record(row: dict) -> tuple[float, APRecord] | None:
    """One beacon or probe-response row -> (time, APRecord), or None for other frames."""
    subtype = _subtype(row)
    freq = _int(_first(row, FREQS))
    bssid = _first(row, (BSSID,))
    if subtype not in (BEACON, PROBE_RESPONSE) or freq is None or not bssid:
        return None

    rsn_codes, wpa_codes = _ints(row, RSN_AKM), _ints(row, WPA_AKM)
    capabilities = _int(_first(row, (CAPABILITIES,)))
    privacy_raw = (_first(row, (PRIVACY,)) or "").lower()
    privacy = privacy_raw in ("1", "true") or bool(capabilities and capabilities & PRIVACY_BIT)
    rsn_present = bool(rsn_codes or _values(row, RSN_PAIRWISE) or _values(row, RSN_MFPC))
    wpa_present = bool(wpa_codes or _values(row, WPA_PAIRWISE))
    security, akm, pairwise = security_from_suites(
        rsn_codes if rsn_present else None, wpa_codes if wpa_present else None,
        _ints(row, RSN_PAIRWISE) + _ints(row, WPA_PAIRWISE), privacy)
    signal = _first(row, SIGNALS)

    record = APRecord(
        bssid=bssid,
        ssid=_decode_ssid(row.get(SSID) or ""),
        freq_mhz=freq,
        signal_dbm=float(signal) if signal is not None else None,
        security=security,
        akm=akm,
        pairwise=pairwise,
        beacon_interval=_int(_first(row, (BEACON_INTERVAL,))),
        capabilities=capabilities,
        tsf=_int(_first(row, (TSF,))),
        label=map_label(row.get(LABEL)),
    )
    return float(row[TIME]), record


def windows(rows: Iterable[dict], window_s: float, meta: dict) -> Iterator[Snapshot]:
    """Group frames into `window_s`-second Snapshots. Rows must be in capture order."""
    parsed = (p for p in map(frame_to_record, rows) if p is not None)
    return windowed(parsed, window_s, "awid3", meta)


def read_csv(path: Path) -> Iterator[dict]:
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        check_columns(reader.fieldnames or [], path)
        yield from reader


def check_columns(columns: list[str], source: Path) -> None:
    missing = [c for c in REQUIRED if c not in columns]
    if SUBTYPE not in columns and not all(c in columns for c in SUBTYPE_PARTS):
        missing.append(f"{SUBTYPE} or {' and '.join(SUBTYPE_PARTS)}")
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


def _tsf_below(row: dict, limit_us: float) -> bool:
    tsf = _first(row, (TSF,))
    return tsf is not None and _int(tsf) < limit_us


def convert(source: Path, out: Path, window_s: float = 10.0, ssid: str | None = None,
            evil_bssids: Iterable[str] = (), evil_tsf_below: float | None = None,
            scenario: str | None = None) -> Counter:
    """Convert one AWID3 file to a JSONL recording. Returns AP-window counts per label."""
    rows = read_pcap(source) if source.suffix in (".pcap", ".pcapng", ".cap") else read_csv(source)
    evil = {b.lower() for b in evil_bssids}
    if evil:
        rows = ({**row, LABEL: "Evil_Twin"} if (row.get(BSSID) or "").lower() in evil else row
                for row in rows)
    if evil_tsf_below is not None:
        limit = evil_tsf_below * 1e6
        rows = ({**row, LABEL: "Evil_Twin"} if _tsf_below(row, limit) else row for row in rows)
    meta = {"dataset": "awid3", "file": source.name, **({"ssid": ssid} if ssid else {}),
            **({"scenario": scenario} if scenario else {})}
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
    parser.add_argument("--ssid", help="trusted network, stored in meta['ssid']")
    parser.add_argument("--evil-bssid", action="append", default=[], metavar="BSSID",
                        help="label every frame of this BSSID evil_twin (repeatable)")
    parser.add_argument("--scenario", help="attack name stored in meta['scenario']")
    parser.add_argument("--evil-tsf-below", type=float, metavar="SECONDS",
                        help="label every frame whose TSF is below this evil_twin (BSSID clones)")
    args = parser.parse_args(argv)
    try:
        counts = convert(args.input, args.out, args.window, args.ssid, args.evil_bssid,
                         args.evil_tsf_below, args.scenario)
    except (AwidError, OSError) as e:
        sys.exit(f"error: {e}")
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"{args.out}: {summary or 'no beacons found'}")


if __name__ == "__main__":
    main()
