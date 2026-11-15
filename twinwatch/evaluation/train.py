"""Train the Random Forest detector with origin-grouped cross-validation.

Every labelled AP seen after a session's baseline becomes one row of signals.
Rows are grouped by origin (the source recording and SSID a session came
from), not by session: synthetic sessions built from one source share its
devices, so splitting them by session would leak. Out-of-fold predictions are
compared with the naive and weighted rules on the same rows, then the final
model is fitted on all rows.

Usage:
    python -m twinwatch.evaluation.train IN.jsonl [IN2.jsonl ...] [-o models/twinwatch_rf.joblib]
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from twinwatch import baseline as baseline_mod
from twinwatch import features, recording
from twinwatch.detectors import DETECTORS, SUSPICIOUS_AT
from twinwatch.detectors.ml import DEFAULT_MODEL
from twinwatch.model import BENIGN, EVIL_TWIN

LEARN_SCANS = 6  # baseline length for recordings without meta["learn_scans"]


@dataclass
class Dataset:
    X: list[list[float]] = field(default_factory=list)
    y: list[int] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    scenarios: list[str] = field(default_factory=list)
    signals: list[dict[str, float]] = field(default_factory=list)
    synthetic: int = 0


def load(paths: list[Path]) -> Dataset:
    data = Dataset()
    for path in paths:
        for (_, ssid), snaps in recording.sessions(recording.read(path), path.stem).items():
            meta = snaps[0].meta
            learn = meta.get("learn_scans", LEARN_SCANS)
            if not ssid or len(snaps) <= learn:
                continue
            baseline = baseline_mod.build(snaps[:learn], ssid)
            group = f"{meta.get('origin', path.stem)}|{ssid}"
            for snap in snaps[learn:]:
                for ap in snap.for_ssid(ssid):
                    if ap.label not in (BENIGN, EVIL_TWIN):
                        continue
                    signals = features.extract(ap, baseline)
                    data.X.append([signals[n] for n in features.SIGNALS])
                    data.y.append(int(ap.label == EVIL_TWIN))
                    data.groups.append(group)
                    data.scenarios.append(meta.get("scenario", "recorded"))
                    data.signals.append(signals)
                    data.synthetic += meta.get("dataset") == "synthetic"
    return data


def new_forest(seed: int):
    from sklearn.ensemble import RandomForestClassifier

    return RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced",
                                  random_state=seed, n_jobs=-1)


def cross_validate(data: Dataset, seed: int) -> list[float] | None:
    """Out-of-fold probabilities, or None with fewer than two origins."""
    from sklearn.model_selection import GroupKFold

    n_groups = len(set(data.groups))
    if n_groups < 2:
        return None
    oof = [0.0] * len(data.y)
    for train, test in GroupKFold(n_splits=min(5, n_groups)).split(data.X, data.y, data.groups):
        if len({data.y[i] for i in train}) < 2:
            continue
        model = new_forest(seed).fit([data.X[i] for i in train], [data.y[i] for i in train])
        for i, p in zip(test, model.predict_proba([data.X[i] for i in test])[:, 1]):
            oof[i] = float(p)
    return oof


def rates(scores: list[float], data: Dataset) -> dict[str, float]:
    """Share of rows flagged (score >= Suspicious) per scenario and label."""
    flagged, total = Counter(), Counter()
    for score, y, scenario in zip(scores, data.y, data.scenarios):
        key = (scenario, "twin" if y else "benign")
        total[key] += 1
        flagged[key] += score >= SUSPICIOUS_AT
    return {f"{s}/{lab}": flagged[(s, lab)] / total[(s, lab)] for s, lab in sorted(total)}


def summary(scores: list[float], data: Dataset) -> dict[str, float]:
    from sklearn.metrics import roc_auc_score

    twins = [s for s, y in zip(scores, data.y) if y]
    benign = [s for s, y in zip(scores, data.y) if not y]
    out = {
        "detection_rate": sum(s >= SUSPICIOUS_AT for s in twins) / max(1, len(twins)),
        "false_positive_rate": sum(s >= SUSPICIOUS_AT for s in benign) / max(1, len(benign)),
    }
    if twins and benign:
        out["roc_auc"] = float(roc_auc_score(data.y, scores))
    return out


def main(argv: list[str] | None = None) -> None:
    import joblib
    import sklearn
    from rich.console import Console
    from rich.table import Table

    parser = argparse.ArgumentParser(prog="python -m twinwatch.evaluation.train",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("inputs", type=Path, nargs="+", help="labelled JSONL recordings")
    parser.add_argument("-o", "--out", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    console = Console()

    data = load(args.inputs)
    if len(set(data.y)) < 2:
        sys.exit("error: training needs both benign and evil_twin rows")
    n_groups = len(set(data.groups))
    console.print(f"{len(data.y)} rows ({sum(data.y)} twin, {len(data.y) - sum(data.y)} benign) "
                  f"from {n_groups} origins; synthetic share {data.synthetic / len(data.y):.0%}")

    oof = cross_validate(data, args.seed)
    cv = None
    if oof is None:
        console.print("[yellow]Only one origin: no cross-validation possible; add more recordings.[/]")
    else:
        rule_scores = {name: [DETECTORS[name](s)[0] for s in data.signals] for name in DETECTORS}
        results = {"ml": oof, **rule_scores}
        cv = {name: summary(scores, data) for name, scores in results.items()}
        table = Table(title=f"Origin-grouped cross-validation ({min(5, n_groups)} folds), "
                            f"flagged = score >= {SUSPICIOUS_AT}")
        table.add_column("Rows")
        for name in results:
            table.add_column(name, justify="right")
        per_detector = {name: rates(scores, data) for name, scores in results.items()}
        for key in per_detector["ml"]:
            table.add_row(key, *(f"{per_detector[n][key]:.1%}" for n in results))
        for metric in ("detection_rate", "false_positive_rate", "roc_auc"):
            table.add_row(f"[bold]{metric}[/]", *(f"{cv[n][metric]:.3f}" if metric in cv[n] else "-"
                                                  for n in results))
        console.print(table)

    model = new_forest(args.seed).fit(data.X, data.y)
    importance = sorted(zip(features.SIGNALS, model.feature_importances_), key=lambda x: -x[1])
    console.print("Feature importance: " + ", ".join(f"{n} {v:.2f}" for n, v in importance if v >= 0.005))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    info = {"trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "inputs": [p.name for p in args.inputs],
            "rows": len(data.y), "twins": sum(data.y), "origins": sorted(set(data.groups)),
            "synthetic_share": data.synthetic / len(data.y), "cv": cv, "sklearn": sklearn.__version__,
            "seed": args.seed}
    joblib.dump({"model": model, "signals": list(features.SIGNALS), "info": info}, args.out)
    console.print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
