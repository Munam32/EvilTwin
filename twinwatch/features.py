"""Signals for one AP compared with the trusted baseline.

Every detector reads the same signals: the rule detectors weigh them by hand,
the ML detector learns from them. Boolean signals are 0.0 or 1.0. A signal
whose input a source cannot provide (e.g. beacon interval from nmcli, or
`tsf_anomaly` outside monitor mode and AWID3) is 0.0.
"""

from __future__ import annotations

from twinwatch import cluster
from twinwatch.baseline import Baseline
from twinwatch.model import APRecord

SIGNAL_JUMP_DB = 10.0

# Order is fixed: it is the feature-vector order for the ML detector.
SIGNALS = (
    "new_bssid",
    "oui_change",
    "security_downgrade",
    "security_mismatch",
    "channel_jump",
    "channel_unseen",
    "signal_jump",
    "beacon_mismatch",
    "capability_mismatch",
    "cluster_outlier",
    "tsf_anomaly",
    "signal_delta_db",
    "cluster_distance",
)
NUMERIC = {"signal_delta_db", "cluster_distance"}


def extract(ap: APRecord, baseline: Baseline) -> dict[str, float]:
    known = baseline.get(ap.bssid)

    if known:
        profiles = {(known.security, known.akm)}
        min_rank = known.security_rank
        beacons = {known.beacon_interval} - {None}
        caps = {known.capabilities} - {None}
        ref_rssi = known.rssi_median
        jump_db = max(SIGNAL_JUMP_DB, 3 * (known.rssi_spread or 0.0))
    else:
        profiles = baseline.security_profiles
        min_rank = baseline.min_security_rank
        beacons = baseline.beacon_intervals
        caps = baseline.capabilities
        ref_rssi = baseline.strongest_rssi
        jump_db = SIGNAL_JUMP_DB

    delta = ap.signal_dbm - ref_rssi if ap.signal_dbm is not None and ref_rssi is not None else 0.0
    cluster_label, cluster_distance = cluster.clusters_for(baseline).assign(ap)

    values = {
        "new_bssid": known is None,
        "oui_change": ap.oui not in baseline.ouis,
        "security_downgrade": ap.security_rank < min_rank,
        "security_mismatch": (ap.security, ap.akm) not in profiles,
        "channel_jump": known is not None and ap.freq_mhz not in known.freqs,
        "channel_unseen": ap.freq_mhz not in baseline.freqs,
        "signal_jump": delta > jump_db,
        "beacon_mismatch": bool(beacons) and ap.beacon_interval is not None
        and ap.beacon_interval not in beacons,
        "capability_mismatch": bool(caps) and ap.capabilities is not None
        and ap.capabilities not in caps,
        "cluster_outlier": cluster_label == -1,
        "tsf_anomaly": bool(ap.tsf_backwards),
        "signal_delta_db": delta,
        "cluster_distance": cluster_distance,
    }
    return {name: float(values[name]) for name in SIGNALS}


def fired(signals: dict[str, float]) -> tuple[str, ...]:
    """Boolean signals that are on, in SIGNALS order."""
    return tuple(n for n in SIGNALS if n not in NUMERIC and signals[n])
