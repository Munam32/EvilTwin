"""Weighted-signal baseline: hand-weighted sum of fired signals, capped at 1.

Weights are set by reasoning about the attack, not fitted to data:
- A new BSSID alone is normal in multi-AP networks, so it stays below the
  Suspicious threshold (0.4) on its own.
- A security downgrade is the clearest attack sign, so with a new BSSID it
  reaches Likely evil twin (0.75).
- A known BSSID on a channel it never used is the cloned-BSSID pattern.
- A new legitimate AP on a new channel (0.30 + 0.05) must stay Safe.
"""

from __future__ import annotations

from twinwatch.features import fired

WEIGHTS = {
    "new_bssid": 0.30,
    "oui_change": 0.25,
    "security_downgrade": 0.50,
    "security_mismatch": 0.25,
    "channel_jump": 0.45,
    "channel_unseen": 0.05,
    "signal_jump": 0.15,
    "beacon_mismatch": 0.20,
    "capability_mismatch": 0.20,
}


def score(signals: dict[str, float]) -> tuple[float, tuple[str, ...]]:
    reasons = tuple(sorted(fired(signals), key=lambda n: -WEIGHTS[n]))
    return min(1.0, sum(WEIGHTS[n] for n in reasons)), reasons
