import random

import pytest

from twinwatch import baseline as baseline_mod
from twinwatch.datasets import synth
from twinwatch.detectors import DETECTORS, LIKELY, SAFE, assess
from twinwatch.features import extract
from twinwatch.lookalike import looks_alike, normalise
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot


@pytest.mark.parametrize("candidate, trusted", [
    (" KARIMM", "Karim"),          # WPA3 Attacks Dataset twin
    ("HOMENET", "HomeNet"),
    ("Home Net", "HomeNet"),
    ("H0meNet", "HomeNet"),
    ("HomeNett", "HomeNet"),
    ("Starbuck5", "Starbucks"),
    ("CafeCornre", "CafeCorner"),  # two edits on a long name
    ("Caferna", "Cafema"),         # rn looks like m
    ("Office 3", "Office3"),       # same number, other spacing
])
def test_lookalikes(candidate, trusted):
    assert looks_alike(candidate, trusted)


@pytest.mark.parametrize("candidate, trusted", [
    ("HomeNet", "HomeNet"),        # the network itself
    ("HomeNet_5G", "HomeNet"),     # sibling band network
    ("HomeNet-2.4GHz", "HomeNet_5G"),
    ("OfficeWiFi", "HomeNet"),
    ("Lab2", "Lab1"),              # numbered networks
    ("", "HomeNet"),
    ("HomeNetGuest", "HomeNet"),
    ("HomeNet-EXT", "HomeNet"),     # extender
    ("HomeNet 4G", "HomeNet 5G"),   # "4G" written for 2.4 GHz
    ("Home_2.4G_x", "Home_5G_x"),   # band in the middle
    ("HomeNet.4G", "HomeNet.5G"),
    ("Home-2", "Home"),
    ("TP-Link_31A6", "TP-Link_A886"),
    ("a66924a0", "a6692634"),
    ("(^_^)", "✨"),                 # nothing left after normalising
])
def test_not_lookalikes(candidate, trusted):
    assert not looks_alike(candidate, trusted)


def test_normalise_folds_case_spacing_and_confusables():
    assert normalise(" H0me-Net ") == normalise("homenet")


def ap(bssid, ssid="HomeNet", signal=-50.0, label=BENIGN):
    return APRecord(bssid=bssid, ssid=ssid, freq_mhz=2412, signal_dbm=signal, security=("WPA2",),
                    akm=("PSK",), label=label)


REAL = "02:00:00:00:01:01"
NEIGHBOUR = "02:00:00:00:02:01"  # "HomeNet " next door, seen while learning
TWIN = "0a:11:22:33:44:55"


def learned():
    snaps = [Snapshot(float(i), "t", (ap(REAL), ap(NEIGHBOUR, "HomeNet "), ap("02:00:00:00:03:01", "Other")))
             for i in range(3)]
    return baseline_mod.build(snaps, "HomeNet")


def test_baseline_keeps_lookalike_neighbours_and_round_trips():
    base = learned()
    assert base.neighbours == (NEIGHBOUR,) and [a.bssid for a in base.aps] == [REAL]
    assert baseline_mod.Baseline.from_dict(base.to_dict()) == base
    old = {k: v for k, v in base.to_dict().items() if k != "neighbours"}  # stored before this field
    assert baseline_mod.Baseline.from_dict(old).neighbours == ()


def test_new_lookalike_ap_is_checked_and_flagged():
    base = learned()
    snap = Snapshot(9.0, "t", (ap(REAL), ap(NEIGHBOUR, "HomeNet "), ap(TWIN, " HOMENET", label=EVIL_TWIN),
                               ap("02:00:00:00:03:01", "Other")))
    assert [a.bssid for a in base.candidates(snap)] == [REAL, TWIN]
    assert extract(base.candidates(snap)[1], base)["ssid_lookalike"] == 1.0
    verdicts = {v.ap.bssid: v for v in assess(DETECTORS["weighted"], snap, base)}
    assert verdicts[TWIN].level == LIKELY and "ssid_lookalike" in verdicts[TWIN].reasons
    assert verdicts[REAL].level == SAFE


def test_synthetic_lookalike_names():
    rng = random.Random(0)
    for ssid in ("HomeNet", "Karim", "ab", "FBI_5G", "#SFO FREE WIFI"):
        for _ in range(20):
            name = synth.lookalike_name(ssid, rng)
            assert name != ssid and looks_alike(name, ssid)


@pytest.mark.parametrize("candidate, trusted, kind", [
    ("HomeNet_5G", "HomeNet", "sibling"),
    ("HomeNet-EXT", "HomeNet", "sibling"),
    ("HomeNet 4G", "HomeNet 5G", "sibling"),
    ("Lab2", "Lab1", "sibling"),
    ("5G", "2.4G", None),          # no core name left
    (" HOMENET", "HomeNet", "lookalike"),
    ("OfficeWiFi", "HomeNet", None),
])
def test_relation(candidate, trusted, kind):
    from twinwatch.lookalike import relation
    assert relation(candidate, trusted) == kind


def test_new_sibling_is_suspicious_but_learned_sibling_is_trusted():
    snaps = [Snapshot(float(i), "t", (ap(REAL), ap(NEIGHBOUR, "HomeNet_Guest"))) for i in range(3)]
    base = baseline_mod.build(snaps, "HomeNet")
    assert base.neighbours == (NEIGHBOUR,)
    later = Snapshot(9.0, "t", (ap(REAL), ap(NEIGHBOUR, "HomeNet_Guest"),
                                ap("02:00:00:00:01:09", "HomeNet_5G", label=EVIL_TWIN)))
    verdicts = {v.ap.bssid: v for v in assess(DETECTORS["weighted"], later, base)}
    assert NEIGHBOUR not in verdicts
    sibling = verdicts["02:00:00:00:01:09"]  # same vendor as the real AP: name and new BSSID only
    assert sibling.signals["ssid_sibling"] == 1.0 and sibling.signals["ssid_lookalike"] == 0.0
    assert sibling.level == "Suspicious"


def test_sibling_names():
    from twinwatch.lookalike import relation
    rng = random.Random(1)
    for ssid in ("HomeNet", "Karim", "FBI_5G"):
        assert all(relation(synth.sibling_name(ssid, rng), ssid) == "sibling" for _ in range(20))
    assert synth.sibling_name("ab", rng) != "ab"  # too short for siblings: falls back to a lookalike


def raw(bssid, ssid, lat=31.48, lon=74.30, encryption="wpa2"):
    return {"netid": bssid, "ssid": ssid, "trilat": lat, "trilong": lon, "channel": 6,
            "encryption": encryption}


def test_neighbour_pairs_and_pair_sessions(tmp_path):
    from twinwatch import recording
    from twinwatch.datasets import wigle
    records = [raw("02:00:00:00:01:01", "CafeNet"), raw("02:00:00:00:01:02", "CafeNet"),
               raw("0a:00:00:00:02:01", "CafeNet_5G"), raw("0e:00:00:00:03:01", "CAFE NET", encryption="none"),
               raw("02:00:00:00:04:01", "Unrelated"), raw("0e:00:00:00:05:01", "CafeNet", lat=31.60)]
    pairs = wigle.neighbour_pairs(records)
    kinds = {(p.meta["ssid"], p.meta["neighbour_ssid"]): p.meta["relation"] for p in pairs}
    assert kinds[("CafeNet", "CafeNet_5G")] == "sibling" and kinds[("CafeNet", "CAFE NET")] == "lookalike"
    assert ("CafeNet", "Unrelated") not in kinds

    src, out = tmp_path / "pairs.jsonl", tmp_path / "syn.jsonl"
    for p in pairs:
        recording.append(src, p)
    counts = synth.generate([src], out, learn_scans=3, attack_scans=2, seed=0)
    assert counts["benign_lookalike"] == counts["lookalike_ssid"] > 0
    assert counts["benign_sibling"] == counts["sibling_ssid"] > 0
    benign = [s for s in recording.read(out) if s.meta["scenario"] == "benign_lookalike"
              and s.meta["ssid"] == "CafeNet"]
    neighbour = next(a for a in benign[-1].aps if a.ssid == "CAFE NET")
    assert neighbour.label == BENIGN and neighbour.bssid == "0e:00:00:00:03:01"
    assert neighbour.security == ("OPEN",)  # the real neighbour's own fields
    assert not any(a.ssid == "CAFE NET" for s in benign[:3] for a in s.aps)  # absent while learning
