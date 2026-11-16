"""Inject evil twin scenarios into benign recordings (all output labelled synthetic).

Each benign base (one WiGLE cell, or one recording of a network) becomes one
session per scenario: `learn_scans` clean scans for the baseline, then
`attack_scans` scans where the scenario's AP is present. Sessions are tagged
in Snapshot.meta (`session`, `scenario`, `learn_scans`) so training and
evaluation can split by session.

A twin only gets the fields its base has: if the base lacks capability bits
(WiGLE), so does the twin. Otherwise a model could learn "has capability
bits" as the attack sign instead of the attack itself.

For the same reason no single field may separate twins from benign new APs:
some benign new APs carry another vendor prefix (as in real multi-vendor
networks), and some twins copy the real vendor prefix or move to another
channel, so a model has to combine signals.

Usage:
    python -m twinwatch.datasets.synth IN.jsonl [IN2.jsonl ...] -o OUT.jsonl [--seed 0]
"""

from __future__ import annotations

import argparse
import random
import statistics
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from twinwatch import recording
from twinwatch.model import BENIGN, EVIL_TWIN, PRIVACY_BIT, APRecord, Snapshot

BENIGN_SCENARIOS = ("benign_steady", "benign_new_ap")
ATTACK_SCENARIOS = ("same_security", "open_network", "stronger_signal", "cloned_bssid")
SCENARIOS = BENIGN_SCENARIOS + ATTACK_SCENARIOS
# Needs per-beacon TSF data in the base (monitor mode, AWID3): a twin cloning the
# BSSID on the same channel merges into the real AP's record, and only the TSF
# going backwards gives it away.
MONITOR_SCENARIOS = ("cloned_same_channel",)

SCAN_INTERVAL_S = 10.0
DROPOUT = 0.1  # chance an AP is missing from one scan
HOSTAPD_BEACON_TU = 100
HOSTAPD_CAPS = {True: 0x0411, False: 0x0401}  # ESS + ShortSlot, with / without Privacy
# Share of twins configured to copy the real AP's beacon interval and capability bits.
CAREFUL_ATTACKER = 0.5
# Share of benign new APs with a vendor prefix (OUI) the network does not use yet.
# 26% of real WiGLE cells (376 cells, downloaded 2026-11-16) mix more than one OUI.
BENIGN_OTHER_VENDOR = 0.26
# Share of twins whose MAC starts with the real AP's OUI (the attacker picks it).
SPOOFED_OUI = 0.5
# Share of new-BSSID twins on a channel the network does not use (cloned_bssid always is).
TWIN_OTHER_CHANNEL = 0.5
# Twin level relative to the AP it clones (outside stronger_signal): the attacker's
# position is unknown, so it may be heard well below or a little above the real AP.
# A benign new AP may also be up to that much louder than every existing AP.
TWIN_SIGNAL_DB = (-15.0, 5.0)
FREQS = {"2.4": [2412 + 5 * i for i in range(13)],
         "5": [5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825],
         "6": [5955 + 20 * i for i in range(12)]}


def bases(snapshots: Iterable[Snapshot], ssid: str | None, origin: str) -> list[tuple[str, str, list[Snapshot]]]:
    """Benign bases as (origin, ssid, snapshots holding only that SSID's benign APs).

    A WiGLE cell is one base; any other recording is one base.
    """
    groups: dict[tuple[str, str], list[Snapshot]] = defaultdict(list)
    for snap in snapshots:
        name = ssid or snap.meta.get("ssid")
        if not name:
            raise ValueError(f"{origin}: no SSID in the recording; pass --ssid")
        aps = tuple(ap for ap in snap.for_ssid(name) if ap.label != EVIL_TWIN)
        if aps:
            key = f"{origin}@{snap.meta['cell']}" if "cell" in snap.meta else origin
            groups[(key, name)].append(replace(snap, aps=aps))
    return [(key, name, snaps) for (key, name), snaps in groups.items()]


def _random_bssid(rng: random.Random, avoid_ouis: set[str], oui: str | None = None) -> str:
    while True:
        if oui is None:
            first = rng.randrange(0, 256) & 0xFC  # unicast, globally administered
            prefix = ":".join(f"{b:02x}" for b in (first, rng.randrange(256), rng.randrange(256)))
            if prefix in avoid_ouis:
                continue
        else:
            prefix = oui
        return prefix + ":" + ":".join(f"{rng.randrange(256):02x}" for _ in range(3))


def _base_scans(base: list[Snapshot], n: int, rng: random.Random) -> tuple[list[list[APRecord]], bool]:
    """`n` scans cycled from the base with signal noise and dropouts.

    Bases without signal strength (WiGLE) get a simulated level per AP.
    """
    simulated = all(ap.signal_dbm is None for snap in base for ap in snap.aps)
    level = {ap.bssid: rng.uniform(-85, -45) for snap in base for ap in snap.aps}
    scans = []
    for i in range(n):
        aps = []
        for ap in base[i % len(base)].aps:
            signal = level[ap.bssid] if ap.signal_dbm is None else ap.signal_dbm
            aps.append(replace(ap, signal_dbm=round(signal + rng.gauss(0, 2.5), 1), label=BENIGN))
        kept = [ap for ap in aps if rng.random() >= DROPOUT] or aps[:1]
        scans.append(kept)
    return scans, simulated


def has_beacon_tsf(base: list[Snapshot]) -> bool:
    return all(ap.tsf_backwards is not None for snap in base for ap in snap.aps)


def _other_channel(freqs: set[int], band: str, rng: random.Random) -> int:
    choices = [f for f in FREQS[band] if f not in freqs]
    return rng.choice(choices or FREQS[band])


def _injected(scenario: str, target: APRecord, network: list[APRecord], rng: random.Random) -> APRecord | None:
    """The AP a scenario adds next to the real network, or None for benign_steady."""
    ouis = {ap.oui for ap in network}
    freqs = {ap.freq_mhz for ap in network}
    signals = [ap.signal_dbm for ap in network]
    if scenario in ("benign_steady", *MONITOR_SCENARIOS):
        return None
    if scenario == "benign_new_ap":
        freq = rng.choice(sorted(freqs)) if rng.random() < 0.5 else _other_channel(freqs, target.band, rng)
        oui = None if rng.random() < BENIGN_OTHER_VENDOR else target.oui
        return replace(target, bssid=_random_bssid(rng, ouis, oui=oui), freq_mhz=freq,
                       signal_dbm=round(rng.uniform(min(signals), max(signals) + TWIN_SIGNAL_DB[1]), 1),
                       tsf=None if target.tsf is None else rng.randrange(10**6, 10**9), label=BENIGN)

    open_net = scenario == "open_network"
    if rng.random() < CAREFUL_ATTACKER:
        beacon = target.beacon_interval
        caps = None if target.capabilities is None else (
            target.capabilities & ~PRIVACY_BIT if open_net else target.capabilities)
    else:
        beacon = None if target.beacon_interval is None else HOSTAPD_BEACON_TU
        caps = None if target.capabilities is None else HOSTAPD_CAPS[not open_net]
    if scenario == "cloned_bssid":
        bssid, freq = target.bssid, _other_channel(freqs, target.band, rng)
    else:
        bssid = _random_bssid(rng, ouis, oui=target.oui if rng.random() < SPOOFED_OUI else None)
        freq = _other_channel(freqs, target.band, rng) if rng.random() < TWIN_OTHER_CHANNEL else target.freq_mhz
    twin = replace(
        target,
        bssid=bssid,
        freq_mhz=freq,
        signal_dbm=round(target.signal_dbm + (rng.uniform(15, 25) if scenario == "stronger_signal"
                                              else rng.uniform(*TWIN_SIGNAL_DB)), 1),
        security=("OPEN",) if open_net else target.security,
        akm=() if open_net else target.akm,
        pairwise=() if open_net else target.pairwise,
        beacon_interval=beacon,
        capabilities=caps,
        tsf=None if target.tsf is None else rng.randrange(10**6, 10**9),
        label=EVIL_TWIN,
    )
    return twin


def session(origin: str, ssid: str, base: list[Snapshot], scenario: str, learn_scans: int,
            attack_scans: int, rng: random.Random, session_id: str) -> list[Snapshot]:
    if scenario in MONITOR_SCENARIOS and not has_beacon_tsf(base):
        raise ValueError(f"{scenario} needs a base with per-beacon TSF data")
    scans, simulated = _base_scans(base, learn_scans + attack_scans, rng)
    seen: dict[str, list[APRecord]] = defaultdict(list)
    for aps in scans[:learn_scans]:
        for ap in aps:
            seen[ap.bssid].append(ap)
    network = [records[-1] for records in seen.values()]
    # The attacker clones the AP the victim hears best over the learning period.
    target = max(network, key=lambda ap: statistics.median(r.signal_dbm for r in seen[ap.bssid]))
    extra = _injected(scenario, target, network, rng)
    meta = {"dataset": "synthetic", "session": session_id, "scenario": scenario, "ssid": ssid,
            "origin": origin, "learn_scans": learn_scans, "simulated_rssi": simulated}
    snaps = []
    for i, aps in enumerate(scans):
        if scenario == "cloned_same_channel" and i >= learn_scans:
            aps = [replace(ap, tsf_backwards=rng.randint(1, 4), label=EVIL_TWIN)
                   if (ap.bssid, ap.freq_mhz) == (target.bssid, target.freq_mhz) else ap for ap in aps]
        if extra is not None and i >= learn_scans:
            jitter = round(extra.signal_dbm + rng.gauss(0, 2.0), 1)
            aps = [*aps, replace(extra, signal_dbm=jitter)]
        snaps.append(Snapshot(time=i * SCAN_INTERVAL_S, source="synthetic", aps=tuple(aps), meta=meta))
    return snaps


def generate(inputs: list[Path], out: Path, ssid: str | None = None, learn_scans: int = 6,
             attack_scans: int = 6, repeats: int = 1, seed: int = 0) -> dict[str, int]:
    if learn_scans < 1 or attack_scans < 1:
        raise ValueError("learn_scans and attack_scans must be at least 1")
    rng = random.Random(seed)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("")
    counts: dict[str, int] = defaultdict(int)
    for path in inputs:
        for origin, name, base in bases(recording.read(path), ssid, path.stem):
            scenarios = SCENARIOS + (MONITOR_SCENARIOS if has_beacon_tsf(base) else ())
            for r in range(repeats):
                for scenario in scenarios:
                    sid = f"{origin}/{scenario}/{r}"
                    for snap in session(origin, name, base, scenario, learn_scans, attack_scans, rng, sid):
                        recording.append(out, snap)
                    counts[scenario] += 1
    return dict(counts)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m twinwatch.datasets.synth",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("inputs", type=Path, nargs="+", help="benign JSONL recordings")
    parser.add_argument("-o", "--out", type=Path, required=True)
    parser.add_argument("--ssid", help="target SSID when the recordings do not name one")
    parser.add_argument("--learn-scans", type=int, default=6)
    parser.add_argument("--attack-scans", type=int, default=6)
    parser.add_argument("--repeats", type=int, default=1, help="sessions per base and scenario")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    try:
        counts = generate(args.inputs, args.out, args.ssid, args.learn_scans, args.attack_scans,
                          args.repeats, args.seed)
    except (ValueError, OSError) as e:
        sys.exit(f"error: {e}")
    print(f"{args.out}: sessions " + ", ".join(f"{s}={n}" for s, n in counts.items()))


if __name__ == "__main__":
    main()
