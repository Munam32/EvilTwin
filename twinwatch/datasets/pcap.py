"""Monitor-mode pcaps without per-frame labels -> labelled, windowed Snapshots.

For public captures such as the WPA3 Attacks Dataset, where a whole file has
one scenario label. Frames are read with Scapy (no tshark needed) and parsed
like live monitor mode. Each frame is labelled by rules on fields that differ
between the real AP and the twin: a frame matching any --evil rule is
evil_twin, every other frame of --ssid is benign. Only beacons and probe
responses of --ssid and of lookalike or sibling SSIDs (twinwatch.lookalike) are kept. A frame with a hidden (empty) SSID counts as
--ssid when its BSSID has already advertised --ssid: a twin can clone the
BSSID and hide its name, and a scanner groups such frames by BSSID anyway.

A twin that clones the BSSID on the same channel merges with the real AP in
each window (as in live monitor mode); the merged record is evil_twin when
any of its frames is, and its TSF going backwards is the tell.

The detectors learn a baseline from the first `--learn-scans` windows (stored
as meta["learn_scans"]). When the twin is already on air then, as in captures
that start with the attack, the last twin-free windows are moved to the
front and every window is re-timed in the new order (meta["reordered"]).

Usage:
    python -m twinwatch.datasets.pcap IN.pcap -o OUT.jsonl --ssid NAME \\
        --evil beacon_interval=16 --evil capabilities=0x0411 [--window 10] [--learn-scans 6]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

from twinwatch import recording
from twinwatch.beacons import windowed
from twinwatch.lookalike import related
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot

RULE_FIELDS = {"bssid": str, "ssid": str, "freq_mhz": int, "beacon_interval": int, "capabilities": int}

Rule = tuple[str, object]


class PcapError(ValueError):
    pass


def parse_rule(text: str) -> Rule:
    field, sep, value = text.partition("=")
    if not sep or field not in RULE_FIELDS:
        raise argparse.ArgumentTypeError(f"rule is FIELD=VALUE with FIELD in {', '.join(RULE_FIELDS)}")
    if RULE_FIELDS[field] is int:
        try:
            return field, int(value, 0)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{field} needs a number, got {value!r}") from None
    return field, value.lower() if field == "bssid" else value


def label(record: APRecord, rules: list[Rule]) -> APRecord:
    evil = any(getattr(record, field) == value for field, value in rules)
    return replace(record, label=EVIL_TWIN if evil else BENIGN)


def frames(path: Path, ssid: str, rules: list[Rule]) -> Iterator[tuple[float, APRecord]]:
    """(time, labelled record) for every beacon/probe response of `ssid`, in capture order."""
    try:
        from scapy.layers import dot11  # noqa: F401  registers the 802.11 link types
        from scapy.utils import PcapReader
    except ImportError as e:
        raise PcapError("reading pcaps needs scapy: pip install -e '.[monitor]'") from e
    from twinwatch.scan.monitor import frame_to_record

    named: set[str] = set()  # BSSIDs that advertised `ssid`
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            record = frame_to_record(pkt)
            if record is None:
                continue
            if record.ssid == ssid:
                named.add(record.bssid)
            elif not record.ssid and record.bssid in named:
                record = replace(record, ssid=ssid)
            elif not related(record.ssid, ssid):
                continue
            yield float(pkt.time), label(record, rules)


def _has_twin(snap: Snapshot) -> bool:
    return any(ap.label == EVIL_TWIN for ap in snap.aps)


def clean_start(snaps: list[Snapshot], learn_scans: int, window_s: float) -> tuple[list[Snapshot], bool]:
    """Snapshots whose first `learn_scans` are twin-free, moving clean ones from the end if needed."""
    if not any(_has_twin(s) for s in snaps[:learn_scans]):
        return snaps, False
    clean = [i for i, s in enumerate(snaps) if not _has_twin(s)]
    if len(clean) < learn_scans:
        raise PcapError(f"only {len(clean)} twin-free windows; need {learn_scans} for the baseline")
    moved = set(clean[-learn_scans:])
    order = [snaps[i] for i in sorted(moved)] + [s for i, s in enumerate(snaps) if i not in moved]
    t0 = snaps[0].time
    return [replace(s, time=t0 + i * window_s) for i, s in enumerate(order)], True


def convert(source: Path, out: Path, ssid: str, rules: list[Rule], window_s: float = 10.0,
            dataset: str = "pcap", learn_scans: int = 6, scenario: str | None = None) -> Counter:
    """Write windowed Snapshots to `out`. Returns AP-window counts per label."""
    meta = {"dataset": dataset, "file": source.name, "ssid": ssid, "learn_scans": learn_scans,
            **({"scenario": scenario} if scenario else {})}
    snaps = list(windowed(frames(source, ssid, rules), window_s, "pcap", meta))
    snaps, reordered = clean_start(snaps, learn_scans, window_s)
    if reordered:
        snaps = [replace(s, meta={**meta, "reordered": True}) for s in snaps]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("")
    counts: Counter = Counter()
    for snap in snaps:
        recording.append(out, snap)
        counts.update(ap.label for ap in snap.aps)
    counts["snapshots"] = len(snaps)
    counts["reordered"] = int(reordered)
    return counts


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m twinwatch.datasets.pcap",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("input", type=Path, help=".pcap/.pcapng captured in monitor mode")
    parser.add_argument("-o", "--out", type=Path, required=True, help="output .jsonl")
    parser.add_argument("--ssid", required=True, help="network to keep")
    parser.add_argument("--evil", type=parse_rule, action="append", default=[], metavar="FIELD=VALUE",
                        help="frames matching this are the twin (repeatable); none: all benign")
    parser.add_argument("--window", type=float, default=10.0, help="seconds per snapshot")
    parser.add_argument("--dataset", default="pcap", help="name stored in meta['dataset']")
    parser.add_argument("--scenario", help="attack name stored in meta['scenario']")
    parser.add_argument("--learn-scans", type=int, default=6, help="twin-free windows for the baseline")
    args = parser.parse_args(argv)
    try:
        counts = convert(args.input, args.out, args.ssid, args.evil, args.window, args.dataset,
                         args.learn_scans, args.scenario)
    except (PcapError, OSError) as e:
        sys.exit(f"error: {e}")
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"{args.out}: {summary or 'no beacons found'}")


if __name__ == "__main__":
    main()
