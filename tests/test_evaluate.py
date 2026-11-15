import csv
import json

import pytest

from twinwatch import recording
from twinwatch.datasets import synth
from twinwatch.detectors import DETECTORS
from twinwatch.evaluation import evaluate, train
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot

SSID = "HomeNet"
REAL = "02:00:00:00:01:01"
TWIN = "0a:11:22:33:44:55"


def ap(bssid, signal=-50.0, label=BENIGN, caps=0x1431):
    return APRecord(bssid=bssid, ssid=SSID, freq_mhz=2412, signal_dbm=signal, security=("WPA2",),
                    akm=("PSK",), beacon_interval=100, capabilities=caps, label=label)


def lab_session(scenario="stronger_signal"):
    """3 baseline scans, 2 clean scans, then a twin that is weak first and strong after."""
    snaps = [Snapshot(10.0 * i, "test", (ap(REAL),), {"ssid": SSID, "scenario": scenario}) for i in range(5)]
    snaps.append(Snapshot(50.0, "test", (ap(REAL), ap(TWIN, -55.0, EVIL_TWIN, caps=0x1431)),
                          {"ssid": SSID, "scenario": scenario}))
    snaps.append(Snapshot(60.0, "test", (ap(REAL), ap(TWIN, -30.0, EVIL_TWIN, caps=0x1431)),
                          {"ssid": SSID, "scenario": scenario}))
    return snaps


def only_signal_jump(signals):
    return (1.0 if signals["signal_jump"] else 0.0), ()


def test_session_counts_and_time_to_alert():
    scorers = {"jump": only_signal_jump, "weighted": DETECTORS["weighted"]}
    results = {r.detector: r for r in evaluate.evaluate_session(
        lab_session(), SSID, 3, scorers, "s1", "stronger_signal", "lab|HomeNet")}

    jump = results["jump"]
    assert (jump.twin_sightings, jump.twin_flagged) == (2, 1)
    assert (jump.benign_sightings, jump.benign_flagged) == (4, 0)
    assert (jump.twin_first_seen, jump.first_alert, jump.scans_to_alert) == (50.0, 60.0, 1)
    assert jump.time_to_alert == 10.0

    weighted = results["weighted"]  # new BSSID + other vendor: flagged on first sight
    assert weighted.twin_flagged == 2 and weighted.time_to_alert == 0.0 and weighted.scans_to_alert == 0


def test_benign_session_has_no_attack():
    snaps = [Snapshot(float(i), "test", (ap(REAL),), {"ssid": SSID, "scenario": "benign"}) for i in range(5)]
    [r] = evaluate.evaluate_session(snaps, SSID, 3, {"naive": DETECTORS["naive"]}, "b", "benign", "lab")
    assert not r.attack and r.time_to_alert is None and r.benign_sightings == 2


def test_load_sessions_skips_twin_in_baseline(tmp_path, capsys):
    good, bad = tmp_path / "good.jsonl", tmp_path / "bad.jsonl"
    for s in lab_session():
        recording.append(good, s)
    for s in lab_session()[3:]:  # 4 scans; the twin appears in the 3rd, inside the baseline
        recording.append(bad, s)
    sessions = evaluate.load_sessions([good, bad], learn_default=3)
    assert [s[3] for s in sessions] == [f"good:good:{SSID}"]
    assert sessions[0][4:] == ("stronger_signal", f"good|{SSID}")
    assert "evil twin present during the 3 baseline scans" in capsys.readouterr().err


def test_summarize_rates_and_all_row():
    a = evaluate.SessionResult("d", "s1", "attack", "o", twin_sightings=4, twin_flagged=3,
                               benign_sightings=10, benign_flagged=1, twin_first_seen=0.0,
                               first_alert=20.0, scans_to_alert=2)
    b = evaluate.SessionResult("d", "s2", "benign", "o", benign_sightings=10)
    rows = {r["scenario"]: r for r in evaluate.summarize([a, b])}
    assert rows["attack"]["detection_rate"] == 0.75
    assert rows["attack"]["median_time_to_alert_s"] == 20.0
    assert rows["benign"]["detection_rate"] is None and rows["benign"]["sessions_detected"] is None
    assert rows["all"]["false_positive_rate"] == pytest.approx(1 / 20)
    assert rows["all"]["sessions_false_alarm"] == 0.5
    assert list(rows)[-1] == "all"


class FakeModel:
    info = {"origins": ["lab|HomeNet", "other|X"]}


def test_leak_detection():
    sessions = [(None, SSID, 3, "s", "x", "lab|HomeNet")]
    assert evaluate.leaked(sessions, {"ml": FakeModel(), "naive": DETECTORS["naive"]}) == {"ml": ["lab|HomeNet"]}


def test_end_to_end_with_model_and_figures(tmp_path, capsys):
    base = tmp_path / "home.jsonl"
    for i in range(3):
        recording.append(base, Snapshot(float(i), "test", (ap(REAL), ap("02:00:00:00:01:02")), {"ssid": SSID}))
    data = tmp_path / "synthetic.jsonl"
    synth.generate([base], data, learn_scans=3, attack_scans=3, repeats=2, seed=1)
    model = tmp_path / "rf.joblib"
    train.main([str(data), "-o", str(model)])
    out = tmp_path / "results"

    evaluate.main([str(data), "--model", f"ml={model}", "-o", str(out)])

    printed = capsys.readouterr().out
    assert "was trained on test origins" in printed  # same data on purpose: the guard must fire
    assert {p.name for p in out.iterdir()} == {"sessions.csv", "summary.csv", "summary.json",
                                              "detection_false_positives.png", "time_to_alert.png"}
    summary = json.loads((out / "summary.json").read_text())
    detectors = {r["detector"] for r in summary["summary"]}
    assert detectors == {"naive", "weighted", "ml"}
    rows = list(csv.DictReader((out / "sessions.csv").open()))
    assert len(rows) == 3 * len(synth.SCENARIOS) * 2


def test_bad_model_argument(tmp_path):
    with pytest.raises(SystemExit, match="NAME=PATH"):
        evaluate.main([str(tmp_path / "x.jsonl"), "--model", "naive=whatever"])
