"""Naive baseline: any BSSID not in the baseline is an evil twin."""

from __future__ import annotations


def score(signals: dict[str, float]) -> tuple[float, tuple[str, ...]]:
    if signals["new_bssid"]:
        return 1.0, ("new_bssid",)
    return 0.0, ()
