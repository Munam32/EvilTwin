"""Detectors share one interface: a scorer maps an AP's signals to a 0-1 risk score.

`assess` turns scores into verdicts for every AP of the baseline's SSID, so
the CLI and evaluation can swap detectors freely.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from twinwatch import features
from twinwatch.baseline import Baseline
from twinwatch.detectors import naive, weighted
from twinwatch.model import APRecord, Snapshot

SAFE, SUSPICIOUS, LIKELY = "Safe", "Suspicious", "Likely evil twin"
LEVEL_RANK = {SAFE: 0, SUSPICIOUS: 1, LIKELY: 2}
SUSPICIOUS_AT, LIKELY_AT = 0.4, 0.75

# A scorer returns (score in 0..1, signals that drove the score).
Scorer = Callable[[dict[str, float]], tuple[float, tuple[str, ...]]]

# Rule detectors need nothing to run; the ML detector needs a trained model.
DETECTORS: dict[str, Scorer] = {
    "naive": naive.score,
    "weighted": weighted.score,
}
NAMES = (*DETECTORS, "ml")


def make_scorer(name: str, model_path: Path | None = None) -> Scorer:
    if name == "ml":
        from twinwatch.detectors.ml import DEFAULT_MODEL, MLScorer

        return MLScorer.load(model_path or DEFAULT_MODEL)
    return DETECTORS[name]


@dataclass(frozen=True)
class Verdict:
    ap: APRecord
    score: float
    level: str
    reasons: tuple[str, ...]
    signals: dict[str, float]


def level_for(score: float) -> str:
    if score >= LIKELY_AT:
        return LIKELY
    if score >= SUSPICIOUS_AT:
        return SUSPICIOUS
    return SAFE


def assess(scorer: Scorer, snapshot: Snapshot, baseline: Baseline) -> list[Verdict]:
    verdicts = []
    for ap in baseline.candidates(snapshot):
        signals = features.extract(ap, baseline)
        score, reasons = scorer(signals)
        verdicts.append(Verdict(ap, score, level_for(score), reasons, signals))
    return sorted(verdicts, key=lambda v: -v.score)
