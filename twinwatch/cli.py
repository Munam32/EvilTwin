"""Command-line entry point: `twinwatch <command>`."""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import replace
from pathlib import Path

from rich.console import Console

from twinwatch import recording, report
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot
from twinwatch.scan import BACKENDS, ScanError, default_interface, scan

console = Console()


def label_snapshot(snapshot: Snapshot, ssid: str, evil: list[str]) -> Snapshot:
    """Label every AP of `ssid`: evil_twin if it matches an `evil` entry, else benign.

    An entry is `BSSID` or `BSSID@FREQ_MHZ`; the frequency form separates an
    evil twin that clones the real AP's BSSID on another channel.
    """
    evil = [e.lower() for e in evil]

    def is_evil(ap: APRecord) -> bool:
        return ap.bssid in evil or f"{ap.bssid}@{ap.freq_mhz}" in evil

    aps = tuple(
        ap.with_label(EVIL_TWIN if is_evil(ap) else BENIGN) if ap.ssid == ssid else ap
        for ap in snapshot.aps
    )
    return replace(snapshot, aps=aps)


def cmd_scan(args: argparse.Namespace) -> None:
    snap = scan(args.interface, args.backend)
    aps = snap.for_ssid(args.ssid) if args.ssid else snap.aps
    console.print(report.ap_table(aps, title=f"{len(aps)} APs ({snap.source})"))


def cmd_record(args: argparse.Namespace) -> None:
    if args.evil and not args.ssid:
        sys.exit("--evil needs --ssid")
    meta = {k: v for k, v in (("scenario", args.scenario), ("ssid", args.ssid),
                              ("notes", args.notes)) if v}
    n = 0
    while args.count is None or n < args.count:
        started = time.monotonic()
        snap = replace(scan(args.interface, args.backend), meta=meta)
        if args.ssid:
            snap = label_snapshot(snap, args.ssid, args.evil)
        recording.append(args.out, snap)
        n += 1
        seen = len(snap.for_ssid(args.ssid)) if args.ssid else len(snap.aps)
        console.print(f"[{n}] {time.strftime('%H:%M:%S')} recorded {seen} APs -> {args.out}")
        if args.count is None or n < args.count:
            time.sleep(max(0.0, args.interval - (time.monotonic() - started)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="twinwatch", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def scan_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("-i", "--interface", help="wireless interface (default: first found)")
        p.add_argument("--backend", choices=BACKENDS, default="auto")
        p.add_argument("--ssid", help="only this SSID")

    p = sub.add_parser("scan", help="scan once and print the APs")
    scan_options(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("record", help="record scans to a JSONL file for replay and datasets")
    scan_options(p)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument("--interval", type=float, default=10.0, help="seconds between scans")
    p.add_argument("--count", type=int, help="number of scans (default: until Ctrl+C)")
    p.add_argument("--scenario", help="lab scenario name stored in each snapshot")
    p.add_argument("--notes", help="free-text lab notes stored in each snapshot")
    p.add_argument("--evil", action="append", default=[], metavar="BSSID[@FREQ]",
                   help="label this AP of --ssid as evil_twin (repeatable)")
    p.set_defaults(func=cmd_record)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        if getattr(args, "interface", "unset") is None:
            args.interface = default_interface()
        args.func(args)
    except ScanError as e:
        sys.exit(f"error: {e}")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
