"""Detection rate, false-positive rate and time to alert per detector and scenario.

Each test session is replayed: the first `learn_scans` scans build the
baseline, the rest are scored by every detector. "Flagged" means Suspicious or
worse. Measures, per detector and scenario:

- AP level: share of twin sightings flagged (detection rate) and of benign
  sightings flagged (false-positive rate).
- Session level: share of attack sessions where the twin was flagged at least
  once, and of all sessions with any benign AP flagged (false alarm).
- Time to alert: from the first scan with the twin in range to the first scan
  where a twin is flagged, in seconds and scans.

Any number of ML models can be compared (ablations are just other models).
Test sessions from an origin a model was trained on are reported, because
that would leak training data into the test.

Usage:
    python -m twinwatch.evaluation.evaluate data/lab/*.jsonl --model ml=models/twinwatch_rf.joblib [-o results]
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from twinwatch import baseline as baseline_mod
from twinwatch import features, recording
from twinwatch.detectors import DETECTORS, SUSPICIOUS_AT, Scorer
from twinwatch.model import BENIGN, EVIL_TWIN

LEARN_SCANS = 6


@dataclass
class SessionResult:
    detector: str
    session: str
    scenario: str
    origin: str
    twin_sightings: int = 0
    twin_flagged: int = 0
    benign_sightings: int = 0
    benign_flagged: int = 0
    twin_first_seen: float | None = None
    first_alert: float | None = None
    scans_to_alert: int | None = None

    @property
    def attack(self) -> bool:
        return self.twin_sightings > 0

    @property
    def time_to_alert(self) -> float | None:
        if self.twin_first_seen is None or self.first_alert is None:
            return None
        return self.first_alert - self.twin_first_seen


def _score_all(scorer: Scorer, rows: list[dict[str, float]]) -> list[float]:
    many = getattr(scorer, "score_many", None)
    if many is not None:
        return [score for score, _ in many(rows)]
    return [scorer(row)[0] for row in rows]


def evaluate_session(snaps, ssid: str, learn: int, scorers: dict[str, Scorer],
                     session: str, scenario: str, origin: str) -> list[SessionResult]:
    """Score one session's post-baseline scans with every detector."""
    baseline = baseline_mod.build(snaps[:learn], ssid)
    scans = []  # per scan: time and (label, signals) of each labelled AP of the trusted SSID
    for snap in snaps[learn:]:
        aps = [(ap.label, features.extract(ap, baseline))
               for ap in baseline.candidates(snap) if ap.label in (BENIGN, EVIL_TWIN)]
        scans.append((snap.time, aps))
    rows = [signals for _, aps in scans for _, signals in aps]

    results = []
    for name, scorer in scorers.items():
        scores = iter(_score_all(scorer, rows))
        r = SessionResult(name, session, scenario, origin)
        twin_scan = None
        for i, (t, aps) in enumerate(scans):
            for label, _ in aps:
                flagged = next(scores) >= SUSPICIOUS_AT
                if label == EVIL_TWIN:
                    r.twin_sightings += 1
                    r.twin_flagged += flagged
                    if twin_scan is None:
                        twin_scan, r.twin_first_seen = i, t
                    if flagged and r.first_alert is None:
                        r.first_alert, r.scans_to_alert = t, i - twin_scan
                else:
                    r.benign_sightings += 1
                    r.benign_flagged += flagged
        results.append(r)
    return results


def load_sessions(paths: list[Path], learn_default: int):
    """(snapshots, ssid, learn_scans, session id, scenario, origin) per test session."""
    out = []
    for path in paths:
        for (sid, ssid), snaps in recording.sessions(recording.read(path), path.stem).items():
            meta = snaps[0].meta
            learn = meta.get("learn_scans", learn_default)
            if not ssid or len(snaps) <= learn:
                print(f"skipping {path.name}:{ssid or '?'}: needs an SSID and more than {learn} scans",
                      file=sys.stderr)
                continue
            if any(ap.label == EVIL_TWIN for s in snaps[:learn] for ap in s.aps):
                print(f"skipping {path.name}:{ssid}: evil twin present during the {learn} baseline scans",
                      file=sys.stderr)
                continue
            origin = f"{meta.get('origin', path.stem)}|{ssid}"
            out.append((snaps, ssid, learn, f"{path.stem}:{sid}:{ssid}", meta.get("scenario", "unknown"), origin))
    return out


def _rate(num: int, den: int) -> float | None:
    return num / den if den else None


def summarize(results: list[SessionResult]) -> list[dict]:
    """One row per (detector, scenario), plus an 'all' row per detector."""
    groups: dict[tuple[str, str], list[SessionResult]] = defaultdict(list)
    for r in results:
        groups[(r.detector, r.scenario)].append(r)
        groups[(r.detector, "all")].append(r)
    rows = []
    for (detector, scenario), rs in groups.items():
        attacks = [r for r in rs if r.attack]
        delays = [r.time_to_alert for r in attacks if r.time_to_alert is not None]
        scans = [r.scans_to_alert for r in attacks if r.scans_to_alert is not None]
        rows.append({
            "detector": detector, "scenario": scenario, "sessions": len(rs), "attack_sessions": len(attacks),
            "detection_rate": _rate(sum(r.twin_flagged for r in rs), sum(r.twin_sightings for r in rs)),
            "false_positive_rate": _rate(sum(r.benign_flagged for r in rs), sum(r.benign_sightings for r in rs)),
            "sessions_detected": _rate(sum(r.first_alert is not None for r in attacks), len(attacks)),
            "sessions_false_alarm": _rate(sum(r.benign_flagged > 0 for r in rs), len(rs)),
            "median_time_to_alert_s": statistics.median(delays) if delays else None,
            "median_scans_to_alert": statistics.median(scans) if scans else None,
        })
    detectors = list(dict.fromkeys(r.detector for r in results))
    return sorted(rows, key=lambda r: (r["scenario"] == "all", r["scenario"], detectors.index(r["detector"])))


def leaked(sessions, scorers: dict[str, Scorer]) -> dict[str, list[str]]:
    """Per model, test origins it was trained on."""
    out = {}
    test_origins = {s[5] for s in sessions}
    for name, scorer in scorers.items():
        trained = set(getattr(scorer, "info", {}).get("origins", []))
        overlap = sorted(test_origins & trained)
        if overlap:
            out[name] = overlap
    return out


def _fmt(value, pct: bool = True) -> str:
    if value is None:
        return "-"
    return f"{value:.1%}" if pct else f"{value:g}"


def main(argv: list[str] | None = None) -> None:
    from rich.console import Console
    from rich.table import Table

    from twinwatch.detectors.ml import MLScorer, ModelError

    parser = argparse.ArgumentParser(prog="python -m twinwatch.evaluation.evaluate",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("inputs", type=Path, nargs="+", help="labelled test recordings (JSONL)")
    parser.add_argument("--model", action="append", default=[], metavar="NAME=PATH",
                        help="ML model to compare (repeatable), e.g. ml=models/twinwatch_rf.joblib")
    parser.add_argument("--learn-scans", type=int, default=LEARN_SCANS,
                        help="baseline scans for recordings without meta learn_scans")
    parser.add_argument("-o", "--out", type=Path, default=Path("results"))
    parser.add_argument("--no-figures", action="store_true")
    args = parser.parse_args(argv)
    console = Console()

    scorers: dict[str, Scorer] = dict(DETECTORS)
    for spec in args.model:
        name, sep, path = spec.partition("=")
        if not sep or not name or name in scorers:
            sys.exit(f"error: --model wants a new NAME=PATH, got {spec!r}")
        try:
            scorers[name] = MLScorer.load(Path(path))
        except ModelError as e:
            sys.exit(f"error: {e}")

    sessions = load_sessions(args.inputs, args.learn_scans)
    if not sessions:
        sys.exit("error: no usable test sessions")
    for name, origins in leaked(sessions, scorers).items():
        console.print(f"[bold red]Warning:[/] model {name!r} was trained on test origins {origins}; "
                      "its results on them are not a fair test.")

    results = [r for snaps, ssid, learn, sid, scenario, origin in sessions
               for r in evaluate_session(snaps, ssid, learn, scorers, sid, scenario, origin)]
    summary = summarize(results)

    table = Table(title=f"{len(sessions)} test sessions; flagged = score >= {SUSPICIOUS_AT}")
    for col in ("Scenario", "Detector", "Sess.", "Detect", "FP", "Caught", "False alarm", "TTA s", "TTA scans"):
        table.add_column(col, justify="left" if col in ("Scenario", "Detector") else "right")
    previous = None
    for row in summary:
        new_group = row["scenario"] != previous
        if new_group and previous is not None:
            table.add_section()
        table.add_row(row["scenario"] if new_group else "", row["detector"],
                      str(row["sessions"]), _fmt(row["detection_rate"]), _fmt(row["false_positive_rate"]),
                      _fmt(row["sessions_detected"]), _fmt(row["sessions_false_alarm"]),
                      _fmt(row["median_time_to_alert_s"], pct=False), _fmt(row["median_scans_to_alert"], pct=False))
        previous = row["scenario"]
    console.print(table)
    console.print("Detect / FP: share of twin / benign AP sightings flagged. Caught: attack sessions with a "
                  "flagged twin. False alarm: sessions with any benign AP flagged. TTA: median time to alert.")

    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "sessions.csv").open("w", newline="") as f:
        fields = [*asdict(results[0]), "time_to_alert"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({**asdict(r), "time_to_alert": r.time_to_alert})
    with (args.out / "summary.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    (args.out / "summary.json").write_text(json.dumps({
        "inputs": [p.name for p in args.inputs], "threshold": SUSPICIOUS_AT,
        "models": {n: getattr(s, "info", {}) for n, s in scorers.items() if hasattr(s, "info")},
        "summary": summary}, indent=2, default=str))
    written = ["sessions.csv", "summary.csv", "summary.json"]
    if not args.no_figures:
        from twinwatch.evaluation import figures

        written += figures.write_all(summary, results, args.out)
    console.print(f"Wrote {', '.join(written)} to {args.out}/")


if __name__ == "__main__":
    main()
