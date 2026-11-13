from dataclasses import replace

import pytest

from twinwatch import baseline as baseline_mod
from twinwatch import recording
from twinwatch.cli import main
from twinwatch.detectors import DETECTORS, LIKELY, SAFE, SUSPICIOUS, assess, level_for
from twinwatch.features import SIGNALS, extract
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot
from twinwatch.report import Alerter
from twinwatch.store import Store

SSID = "CampusNet"
REAL_A = "02:00:00:00:01:01"
REAL_B = "02:00:00:00:01:02"
TWIN = "0a:11:22:33:44:55"


def ap(bssid, freq=2412, signal=-50.0, security=("WPA2",), akm=("PSK",),
       beacon=100, caps=0x1411, label=None):
    return APRecord(bssid=bssid, ssid=SSID, freq_mhz=freq, signal_dbm=signal,
                    security=security, akm=akm, beacon_interval=beacon,
                    capabilities=caps, label=label)


def legit_scan(t=0.0, jitter=0.0):
    return Snapshot(time=t, source="test", aps=(
        ap(REAL_A, 2412, -50.0 + jitter),
        ap(REAL_B, 5180, -60.0 + jitter),
        APRecord(bssid="02:00:00:00:09:09", ssid="Other", freq_mhz=2437,
                 signal_dbm=-40.0, security=("OPEN",)),
    ))


@pytest.fixture
def baseline():
    return baseline_mod.build([legit_scan(i, jitter=i % 3) for i in range(6)], SSID)


SCENARIOS = {
    "unchanged real AP": ap(REAL_A),
    "new legit AP on new channel": ap("02:00:00:00:01:03", freq=2437),
    "same-security twin": ap(TWIN, caps=0x0411),
    "open twin": ap(TWIN, security=("OPEN",), akm=(), caps=0x0401),
    "stronger-signal twin": ap(TWIN, signal=-30.0),
    "cloned BSSID on other channel": ap(REAL_A, freq=2462, caps=0x0411),
}

EXPECTED = {
    #                                  naive       weighted
    "unchanged real AP":              (SAFE,       SAFE),
    "new legit AP on new channel":    (LIKELY,     SAFE),
    "same-security twin":             (LIKELY,     LIKELY),
    "open twin":                      (LIKELY,     LIKELY),
    "stronger-signal twin":           (LIKELY,     SUSPICIOUS),
    "cloned BSSID on other channel":  (SAFE,       SUSPICIOUS),
}


def test_baseline_fingerprint(baseline):
    assert baseline.scans == 6
    assert [a.bssid for a in baseline.aps] == [REAL_A, REAL_B]
    a = baseline.get(REAL_A)
    assert a.freqs == (2412,)
    assert (a.security, a.akm, a.beacon_interval, a.capabilities) == (("WPA2",), ("PSK",), 100, 0x1411)
    assert a.rssi_median == -49.0
    assert a.seen == 6
    assert baseline.strongest_rssi == -49.0


def test_baseline_without_ssid_fails():
    with pytest.raises(ValueError, match="no AP"):
        baseline_mod.build([legit_scan()], "Missing")


def test_store_round_trip(tmp_path, baseline):
    store = Store(tmp_path / "tw.db")
    assert store.load(SSID) is None
    store.save(baseline)
    assert Store(tmp_path / "tw.db").load(SSID) == baseline
    assert store.ssids() == [SSID]


def test_signals_open_twin(baseline):
    s = extract(SCENARIOS["open twin"], baseline)
    assert list(s) == list(SIGNALS)
    assert s["new_bssid"] and s["oui_change"] and s["security_downgrade"]
    assert s["security_mismatch"] and s["capability_mismatch"]
    assert not s["channel_jump"] and not s["beacon_mismatch"]


def test_signals_cloned_bssid(baseline):
    s = extract(SCENARIOS["cloned BSSID on other channel"], baseline)
    assert not s["new_bssid"] and not s["oui_change"]
    assert s["channel_jump"] and s["channel_unseen"] and s["capability_mismatch"]


def test_signal_delta_against_strongest_known_ap(baseline):
    s = extract(SCENARIOS["stronger-signal twin"], baseline)
    assert s["signal_delta_db"] == pytest.approx(19.0)
    assert s["signal_jump"]


def test_missing_fields_do_not_fire(baseline):
    nmcli_like = replace(SCENARIOS["unchanged real AP"], beacon_interval=None, capabilities=None)
    s = extract(nmcli_like, baseline)
    assert not s["beacon_mismatch"] and not s["capability_mismatch"]


@pytest.mark.parametrize("scenario", EXPECTED)
@pytest.mark.parametrize("detector,column", [("naive", 0), ("weighted", 1)])
def test_detector_levels(baseline, scenario, detector, column):
    snap = Snapshot(time=10.0, source="test", aps=(SCENARIOS[scenario],))
    [verdict] = assess(DETECTORS[detector], snap, baseline)
    assert verdict.level == EXPECTED[scenario][column]
    if verdict.level != SAFE:
        assert verdict.reasons


def test_level_thresholds():
    assert [level_for(s) for s in (0.0, 0.39, 0.4, 0.74, 0.75, 1.0)] == \
        [SAFE, SAFE, SUSPICIOUS, SUSPICIOUS, LIKELY, LIKELY]


def test_alerter_raises_only_on_level_increase(tmp_path, baseline):
    alerter = Alerter(tmp_path / "alerts.log", desktop=False)
    scorer = DETECTORS["weighted"]
    stronger = Snapshot(time=1.0, source="test", aps=(ap(REAL_A), SCENARIOS["stronger-signal twin"]))
    open_twin = Snapshot(time=2.0, source="test", aps=(ap(REAL_A), SCENARIOS["open twin"]))

    assert [v.level for v in alerter.update(assess(scorer, stronger, baseline))] == [SUSPICIOUS]
    assert alerter.update(assess(scorer, stronger, baseline)) == []
    assert [v.level for v in alerter.update(assess(scorer, open_twin, baseline))] == [LIKELY]

    lines = (tmp_path / "alerts.log").read_text().splitlines()
    assert len(lines) == 2
    assert TWIN in lines[1] and "security_downgrade" in lines[1]


def test_replay_learns_from_recording(tmp_path, capsys):
    path = tmp_path / "lab.jsonl"
    for i in range(3):
        recording.append(path, replace(legit_scan(i), meta={"ssid": SSID}))
    attack = Snapshot(time=5.0, source="test", meta={"ssid": SSID}, aps=(
        ap(REAL_A, label=BENIGN), ap(TWIN, security=("OPEN",), akm=(), caps=0x0401, label=EVIL_TWIN)))
    recording.append(path, attack)

    main(["replay", str(path), "--learn-scans", "3", "--detector", "weighted"])

    out = capsys.readouterr().out
    assert "1 snapshots" in out
    assert "evil_twin" in out and "benign" in out
