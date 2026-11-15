"""DBSCAN grouping of the trusted network's APs by device fingerprint.

A fingerprint is what describes the device, not where it is: vendor prefix,
security profile, beacon interval and capability bits. Signal and channel are
left out; other signals cover them.

DBSCAN runs on the baseline APs. A new AP joins a cluster when it lies within
`eps` of one of the cluster's core APs, as in DBSCAN's own rule for new
points; otherwise it is an outlier.

`min_samples` is fixed at 1: baseline APs are trusted (trust on first use), so
none may be noise. Each is a core point, and a network of unlike devices (e.g.
a router plus an extender from another vendor) forms several clusters with no
outliers. Higher values mark such legitimate APs as noise.

Tuning:
    python -m twinwatch.cluster tune RECORDING.jsonl [...]
"""

from __future__ import annotations

import argparse
import functools
from collections.abc import Iterable
from dataclasses import dataclass

from twinwatch.baseline import Baseline, BaselineAP
from twinwatch.model import APRecord

# Below 0.25, the distance of a twin that differs only in vendor prefix when
# all four attributes are known. Chosen with `tune` on home-network data.
EPS = 0.2
MIN_SAMPLES = 1


@dataclass(frozen=True)
class Fingerprint:
    oui: str
    security: tuple[str, ...]
    akm: tuple[str, ...]
    security_rank: int
    beacon_interval: int | None
    capabilities: int | None


def fingerprint(ap: APRecord | BaselineAP) -> Fingerprint:
    return Fingerprint(ap.bssid[:8], ap.security, ap.akm, ap.security_rank,
                       ap.beacon_interval, ap.capabilities)


def distance(a: Fingerprint, b: Fingerprint) -> float:
    """Gower-style distance in [0, 1]: the mean of per-attribute distances.

    Attributes unknown on either side (e.g. no capability bits from WiGLE or
    nmcli) are skipped rather than counted as matches or mismatches.
    """
    parts = [
        float(a.oui != b.oui),
        0.5 * ((a.security, a.akm) != (b.security, b.akm)) + 0.5 * abs(a.security_rank - b.security_rank) / 4,
    ]
    if a.beacon_interval is not None and b.beacon_interval is not None:
        parts.append(float(a.beacon_interval != b.beacon_interval))
    if a.capabilities is not None and b.capabilities is not None:
        union = a.capabilities | b.capabilities
        parts.append(bin(a.capabilities ^ b.capabilities).count("1") / bin(union).count("1") if union else 0.0)
    return sum(parts) / len(parts)


class NetworkClusters:
    """DBSCAN clusters of one baseline's APs."""

    def __init__(self, aps: Iterable[BaselineAP], eps: float = EPS):
        from sklearn.cluster import DBSCAN

        self.eps = eps
        self.fingerprints = [fingerprint(ap) for ap in aps]
        matrix = [[distance(a, b) for b in self.fingerprints] for a in self.fingerprints]
        db = DBSCAN(eps=eps, min_samples=MIN_SAMPLES, metric="precomputed").fit(matrix)
        self.labels = [int(label) for label in db.labels_]
        self.core = [int(i) for i in db.core_sample_indices_]

    @property
    def n_clusters(self) -> int:
        return len(set(self.labels))

    def assign(self, ap: APRecord) -> tuple[int, float]:
        """(cluster label, distance to the nearest core AP); label -1 means outlier."""
        fp = fingerprint(ap)
        dist, nearest = min((distance(fp, self.fingerprints[i]), i) for i in self.core)
        return (self.labels[nearest] if dist <= self.eps else -1), dist


@functools.lru_cache(maxsize=32)
def clusters_for(baseline: Baseline, eps: float = EPS) -> NetworkClusters:
    return NetworkClusters(baseline.aps, eps)


def tune(sessions: list[tuple[Baseline, list[APRecord]]], eps_grid: Iterable[float]) -> list[dict]:
    """Outlier rates per eps over labelled APs seen after each baseline.

    `twin_outlier` should be high, `benign_outlier` (known and new legitimate
    APs) low.
    """
    rows = []
    for eps in eps_grid:
        flagged = {"benign": [0, 0], "evil_twin": [0, 0]}
        for baseline, aps in sessions:
            clusters = NetworkClusters(baseline.aps, eps)
            for ap in aps:
                if ap.label in flagged:
                    flagged[ap.label][0] += clusters.assign(ap)[0] == -1
                    flagged[ap.label][1] += 1
        rows.append({
            "eps": eps,
            "benign_outlier": flagged["benign"][0] / max(1, flagged["benign"][1]),
            "twin_outlier": flagged["evil_twin"][0] / max(1, flagged["evil_twin"][1]),
            "benign_n": flagged["benign"][1], "twin_n": flagged["evil_twin"][1],
        })
    return rows


def recommend(rows: list[dict], max_benign_outlier: float, tolerance: float = 0.10) -> dict | None:
    """Largest eps whose twin outlier rate is within `tolerance` of the best.

    Synthetic legitimate APs copy their vendor's exact settings, so benign
    outlier rates barely penalize a small eps. Real legitimate APs vary a
    little, so the largest eps that still flags twins is preferred.
    """
    ok = [r for r in rows if r["benign_outlier"] <= max_benign_outlier]
    if not ok:
        return None
    best = max(r["twin_outlier"] for r in ok)
    return max((r for r in ok if r["twin_outlier"] >= best - tolerance), key=lambda r: r["eps"])


def _labelled_sessions(paths: list) -> list[tuple[Baseline, list[APRecord]]]:
    from twinwatch import baseline as baseline_mod
    from twinwatch import recording

    out = []
    for path in paths:
        for (_, ssid), snaps in recording.sessions(recording.read(path), path.stem).items():
            learn = snaps[0].meta.get("learn_scans", min(6, len(snaps) // 2))
            if not ssid or learn < 1 or len(snaps) <= learn:
                continue
            baseline = baseline_mod.build(snaps[:learn], ssid)
            out.append((baseline, [ap for s in snaps[learn:] for ap in s.for_ssid(ssid)]))
    return out


def main(argv: list[str] | None = None) -> None:
    from pathlib import Path

    from rich.console import Console
    from rich.table import Table

    parser = argparse.ArgumentParser(prog="python -m twinwatch.cluster", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("tune", help="outlier rates for a grid of eps")
    p.add_argument("recordings", type=Path, nargs="+", help="labelled JSONL (synthetic or lab)")
    p.add_argument("--max-benign-outlier", type=float, default=0.05)
    args = parser.parse_args(argv)

    sessions = _labelled_sessions(args.recordings)
    rows = tune(sessions, [round(0.05 * i, 2) for i in range(1, 13)])
    table = Table(title=f"DBSCAN tuning over {len(sessions)} sessions")
    for col in ("eps", "benign outlier", "twin outlier"):
        table.add_column(col, justify="right")
    for r in rows:
        table.add_row(f"{r['eps']:.2f}", f"{r['benign_outlier']:.1%}", f"{r['twin_outlier']:.1%}")
    console = Console()
    console.print(table)
    best = recommend(rows, args.max_benign_outlier)
    if best:
        console.print(f"Recommended eps={best['eps']:.2f}: twins flagged {best['twin_outlier']:.1%}, "
                      f"benign {best['benign_outlier']:.1%}, over {best['twin_n']} twin and "
                      f"{best['benign_n']} benign AP sightings")
    else:
        console.print(f"No setting keeps benign outliers <= {args.max_benign_outlier:.0%}")


if __name__ == "__main__":
    main()
