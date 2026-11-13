"""Command-line entry point: `twinwatch <command>`."""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

from rich.console import Console

from twinwatch import baseline as baseline_mod
from twinwatch import recording, report
from twinwatch.detectors import DETECTORS, SAFE, assess
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot
from twinwatch.scan import BACKENDS, ScanError, default_interface, scan
from twinwatch.store import Store, data_dir, default_db

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


def scan_loop(args: argparse.Namespace, count: int | None) -> Iterator[Snapshot]:
    """Scan every `args.interval` seconds, `count` times or forever."""
    n = 0
    while count is None or n < count:
        started = time.monotonic()
        yield scan(args.interface, args.backend)
        n += 1
        if count is None or n < count:
            time.sleep(max(0.0, args.interval - (time.monotonic() - started)))


def cmd_scan(args: argparse.Namespace) -> None:
    snap = scan(args.interface, args.backend)
    aps = snap.for_ssid(args.ssid) if args.ssid else snap.aps
    console.print(report.ap_table(aps, title=f"{len(aps)} APs ({snap.source})"))


def cmd_record(args: argparse.Namespace) -> None:
    if args.evil and not args.ssid:
        sys.exit("--evil needs --ssid")
    meta = {k: v for k, v in (("scenario", args.scenario), ("ssid", args.ssid),
                              ("notes", args.notes)) if v}
    for n, snap in enumerate(scan_loop(args, args.count), 1):
        snap = replace(snap, meta=meta)
        if args.ssid:
            snap = label_snapshot(snap, args.ssid, args.evil)
        recording.append(args.out, snap)
        seen = len(snap.for_ssid(args.ssid)) if args.ssid else len(snap.aps)
        console.print(f"[{n}] {time.strftime('%H:%M:%S')} recorded {seen} APs -> {args.out}")


def cmd_learn(args: argparse.Namespace) -> None:
    store = Store(args.db)
    if store.load(args.ssid) and not args.force:
        sys.exit(f"a baseline for {args.ssid!r} exists; pass --force to replace it")
    console.print(f"Learning {args.ssid!r}: {args.scans} scans, {args.interval:.0f}s apart. "
                  "Only do this on a network you trust.")
    snaps = []
    for n, snap in enumerate(scan_loop(args, args.scans), 1):
        snaps.append(snap)
        console.print(f"[{n}/{args.scans}] {len(snap.for_ssid(args.ssid))} APs")
    try:
        baseline = baseline_mod.build(snaps, args.ssid)
    except ValueError as e:
        sys.exit(f"error: {e}")
    store.save(baseline)
    console.print(report.baseline_table(baseline))
    console.print(f"Saved to {args.db}")


def _load_baseline(db: Path, ssid: str) -> baseline_mod.Baseline:
    baseline = Store(db).load(ssid)
    if baseline is None:
        sys.exit(f"no baseline for {ssid!r}; run `twinwatch learn --ssid {ssid!r}` first")
    return baseline


def cmd_watch(args: argparse.Namespace) -> None:
    baseline = _load_baseline(args.db, args.ssid)
    scorer = DETECTORS[args.detector]
    alerter = report.Alerter(args.log, desktop=not args.no_notify)
    console.print(f"Watching {args.ssid!r} with the {args.detector} detector, every "
                  f"{args.interval:.0f}s. Alerts log: {args.log}. Ctrl+C to stop.")
    for snap in scan_loop(args, None):
        if args.record:
            recording.append(args.record, replace(snap, meta={"ssid": args.ssid}))
        verdicts = assess(scorer, snap, baseline)
        console.print(report.verdict_table(verdicts, f"{time.strftime('%H:%M:%S')} "
                                                     f"{args.ssid!r}: {len(verdicts)} APs"))
        for v in alerter.update(verdicts):
            console.print(f"[bold]ALERT[/] {v.level}: {v.ap.bssid} ({', '.join(v.reasons)})")


def cmd_replay(args: argparse.Namespace) -> None:
    snaps = list(recording.read(args.file))
    if not snaps:
        sys.exit(f"{args.file} has no snapshots")
    ssid = args.ssid or snaps[0].meta.get("ssid")
    if not ssid:
        sys.exit("pass --ssid (the recording does not name one)")
    if args.learn_scans:
        try:
            baseline = baseline_mod.build(snaps[:args.learn_scans], ssid)
        except ValueError as e:
            sys.exit(f"error: {e}")
        snaps = snaps[args.learn_scans:]
    else:
        baseline = _load_baseline(args.db, ssid)

    scorer = DETECTORS[args.detector]
    outcomes: Counter[tuple[str, str]] = Counter()
    for i, snap in enumerate(snaps, 1):
        verdicts = assess(scorer, snap, baseline)
        flagged = [v for v in verdicts if v.level != SAFE]
        if flagged and args.verbose:
            console.print(report.verdict_table(flagged, f"snapshot {i}"))
        for v in verdicts:
            outcomes[(v.ap.label or "unlabelled", v.level)] += 1

    title = (f"{args.detector} on {args.file.name}: {len(snaps)} snapshots, "
             f"baseline {len(baseline.aps)} APs")
    console.print(report.outcome_table(outcomes, title))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="twinwatch", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def scan_options(p: argparse.ArgumentParser, ssid_required: bool = False) -> None:
        p.add_argument("-i", "--interface", help="wireless interface (default: first found)")
        p.add_argument("--backend", choices=BACKENDS, default="auto")
        p.add_argument("--ssid", required=ssid_required,
                       help="trusted network name" if ssid_required else "only this SSID")

    def db_option(p: argparse.ArgumentParser) -> None:
        p.add_argument("--db", type=Path, default=default_db(), help="baseline database")

    def detector_option(p: argparse.ArgumentParser) -> None:
        p.add_argument("--detector", choices=sorted(DETECTORS), default="weighted")

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

    p = sub.add_parser("learn", help="record the baseline fingerprint of a trusted SSID")
    scan_options(p, ssid_required=True)
    db_option(p)
    p.add_argument("--scans", type=int, default=6)
    p.add_argument("--interval", type=float, default=10.0, help="seconds between scans")
    p.add_argument("--force", action="store_true", help="replace an existing baseline")
    p.set_defaults(func=cmd_learn)

    p = sub.add_parser("watch", help="scan periodically and alert on suspicious APs")
    scan_options(p, ssid_required=True)
    db_option(p)
    detector_option(p)
    p.add_argument("--interval", type=float, default=15.0, help="seconds between scans")
    p.add_argument("--log", type=Path, default=data_dir() / "alerts.log")
    p.add_argument("--no-notify", action="store_true", help="no desktop notifications")
    p.add_argument("--record", type=Path, help="also record every scan to this JSONL file")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("replay", help="run a detector over a recorded JSONL file")
    p.add_argument("file", type=Path)
    p.add_argument("--ssid", help="trusted SSID (default: from the recording)")
    db_option(p)
    detector_option(p)
    p.add_argument("--learn-scans", type=int, metavar="N",
                   help="build the baseline from the first N snapshots instead of the database")
    p.add_argument("-v", "--verbose", action="store_true", help="show flagged APs per snapshot")
    p.set_defaults(func=cmd_replay)
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
