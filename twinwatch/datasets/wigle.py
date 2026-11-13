"""WiGLE network search -> benign multi-AP snapshots.

WiGLE stores one record per BSSID (last-seen details and an estimated
location), not scans over time. To get something a laptop could see in one
scan, the APs of one SSID are grouped into ~110 m grid cells; each cell with
at least two APs becomes one Snapshot. WiGLE gives no signal strength, AKM or
capability bits, so those fields stay None.

Two steps, so searches (limited per day) are not repeated:
    python -m twinwatch.datasets.wigle download --ssid NAME --bbox LAT1,LAT2,LON1,LON2 -o data/raw/wigle/NAME.json
    python -m twinwatch.datasets.wigle convert data/raw/wigle/NAME.json -o data/processed/wigle/NAME.jsonl

Credentials come from WIGLE_API_NAME and WIGLE_API_KEY, in the environment or
in a .env file in the working directory.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

from twinwatch import recording
from twinwatch.model import BENIGN, APRecord, Snapshot

SEARCH_URL = "https://api.wigle.net/api/v2/network/search"
PAGE_SIZE = 100  # maximum for API-name/token authentication
CELL_DEG = 0.001  # ~110 m of latitude

# WiGLE's encryption values are 'none', 'wep', 'wpa', 'wpa2', 'wpa3' and 'unknown'.
ENCRYPTION = {"none": ("OPEN",), "wep": ("WEP",), "wpa": ("WPA",), "wpa2": ("WPA2",),
              "wpa3": ("WPA3",)}


class WigleError(RuntimeError):
    pass


def credentials(env_file: Path = Path(".env")) -> tuple[str, str]:
    values = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    values.update({k: v for k, v in os.environ.items() if k.startswith("WIGLE_")})
    name, key = values.get("WIGLE_API_NAME"), values.get("WIGLE_API_KEY")
    if not name or not key:
        raise WigleError("set WIGLE_API_NAME and WIGLE_API_KEY in the environment or .env")
    return name, key


def parse_bbox(text: str) -> tuple[float, float, float, float]:
    try:
        lat1, lat2, lon1, lon2 = (float(v) for v in text.split(","))
    except ValueError:
        raise argparse.ArgumentTypeError("bbox is LAT1,LAT2,LON1,LON2") from None
    return min(lat1, lat2), max(lat1, lat2), min(lon1, lon2), max(lon1, lon2)


def search(ssid: str, bbox: tuple[float, float, float, float], max_results: int,
           auth: tuple[str, str]) -> list[dict]:
    """All WiFi records named exactly `ssid` inside `bbox`, up to `max_results`."""
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    lat1, lat2, lon1, lon2 = bbox
    params = {"ssid": ssid, "latrange1": lat1, "latrange2": lat2, "longrange1": lon1,
              "longrange2": lon2, "resultsPerPage": min(PAGE_SIZE, max_results)}
    results: list[dict] = []
    while len(results) < max_results:
        url = f"{SEARCH_URL}?{urllib.parse.urlencode(params)}"
        request = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                page = json.load(response)
        except urllib.error.HTTPError as e:
            if e.code == 429 and results:
                print(f"daily query limit reached; keeping {len(results)} results", file=sys.stderr)
                break
            raise WigleError(f"WiGLE search failed: HTTP {e.code} {e.read()[:200]!r}") from e
        if not page.get("success"):
            raise WigleError(f"WiGLE search failed: {page.get('message', page)}")
        results += page.get("results", [])
        if not page.get("searchAfter") or not page.get("results"):
            break
        params["searchAfter"] = page["searchAfter"]
    return results[:max_results]


def _freq(record: dict) -> int | None:
    freq, channel = record.get("frequency") or 0, record.get("channel") or 0
    if freq > 0:
        return freq
    if 1 <= channel <= 13:
        return 2407 + 5 * channel
    if channel == 14:
        return 2484
    if 32 <= channel <= 177:
        return 5000 + 5 * channel
    return None


def to_record(record: dict) -> APRecord | None:
    """WiGLE WiFi record -> APRecord, or None when channel or encryption is unknown."""
    security = ENCRYPTION.get((record.get("encryption") or "").lower())
    freq = _freq(record)
    bssid = record.get("netid") or ""
    if security is None or freq is None or len(bssid) != 17:
        return None
    return APRecord(
        bssid=bssid,
        ssid=record.get("ssid") or "",
        freq_mhz=freq,
        signal_dbm=None,
        security=security,
        beacon_interval=record.get("bcninterval") or None,
        label=BENIGN,
    )


def to_snapshots(records: list[dict], ssid: str, cell_deg: float = CELL_DEG) -> list[Snapshot]:
    """Group APs of `ssid` into grid cells; each cell with 2+ APs becomes one Snapshot."""
    cells: dict[tuple[int, int], dict[str, APRecord]] = defaultdict(dict)
    for raw in records:
        rec = to_record(raw)
        lat, lon = raw.get("trilat"), raw.get("trilong")
        if rec is None or rec.ssid != ssid or lat is None or lon is None:
            continue
        cells[(round(lat / cell_deg), round(lon / cell_deg))][rec.bssid] = rec
    return [
        Snapshot(time=0.0, source="wigle", aps=tuple(sorted(aps.values(), key=lambda a: a.bssid)),
                 meta={"dataset": "wigle", "ssid": ssid, "cell": f"{cy * cell_deg:.3f},{cx * cell_deg:.3f}"})
        for (cy, cx), aps in sorted(cells.items()) if len(aps) >= 2
    ]


def cmd_download(args: argparse.Namespace) -> None:
    results = search(args.ssid, args.bbox, args.max_results, credentials())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"ssid": args.ssid, "bbox": args.bbox, "results": results}))
    print(f"{args.out}: {len(results)} records for {args.ssid!r}")


def cmd_convert(args: argparse.Namespace) -> None:
    data = json.loads(args.input.read_text())
    snaps = to_snapshots(data["results"], data["ssid"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("")
    for snap in snaps:
        recording.append(args.out, snap)
    sizes = sorted(len(s.aps) for s in snaps)
    print(f"{args.out}: {len(snaps)} multi-AP cells, APs per cell "
          f"{sizes[0] if sizes else 0}-{sizes[-1] if sizes else 0}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m twinwatch.datasets.wigle",
                                     description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("download", help="search WiGLE and save the raw records")
    p.add_argument("--ssid", required=True)
    p.add_argument("--bbox", type=parse_bbox, required=True, metavar="LAT1,LAT2,LON1,LON2")
    p.add_argument("--max-results", type=int, default=1000)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_download)
    p = sub.add_parser("convert", help="raw records -> JSONL snapshots")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_convert)
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (WigleError, OSError, KeyError, json.JSONDecodeError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
