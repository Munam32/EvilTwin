import io
import json
import random
import urllib.error
from collections import Counter

import pytest

from twinwatch import baseline as baseline_mod
from twinwatch import recording
from twinwatch.datasets import synth, wigle
from twinwatch.detectors import DETECTORS, SAFE, assess
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot


def wigle_record(bssid, lat, lon, channel=6, frequency=0, encryption="wpa2", bcn=0, ssid="CampusNet"):
    return {"netid": bssid, "ssid": ssid, "trilat": lat, "trilong": lon, "channel": channel,
            "frequency": frequency, "encryption": encryption, "bcninterval": bcn}


RAW = [
    wigle_record("02:00:00:00:01:01", 31.4800, 74.3000, channel=1),
    wigle_record("02:00:00:00:01:02", 31.4801, 74.3002, channel=36),
    wigle_record("02:00:00:00:01:03", 31.4802, 74.2999, frequency=2437, bcn=100),
    wigle_record("02:00:00:00:02:01", 31.5100, 74.3500),  # alone in its cell
    wigle_record("02:00:00:00:03:01", 31.4800, 74.3000, channel=0),  # unknown channel
    wigle_record("02:00:00:00:03:02", 31.4800, 74.3000, encryption="unknown"),
    wigle_record("02:00:00:00:03:03", 31.4800, 74.3000, ssid="Other"),
    wigle_record("02:00:00:00:04:01", 31.6000, 74.4000, encryption="none"),
    wigle_record("02:00:00:00:04:02", 31.6000, 74.4004, channel=11),
]


def test_wigle_record_mapping():
    rec = wigle.to_record(RAW[2])
    assert (rec.freq_mhz, rec.security, rec.beacon_interval, rec.signal_dbm, rec.label) == \
        (2437, ("WPA2",), 100, None, BENIGN)
    assert wigle.to_record(RAW[1]).freq_mhz == 5180
    assert wigle.to_record(RAW[0]).beacon_interval is None
    assert wigle.to_record(RAW[4]) is None
    assert wigle.to_record(RAW[5]) is None
    assert wigle.to_record(RAW[7]).security == ("OPEN",)


def test_wigle_cells_need_two_aps():
    snaps = wigle.to_snapshots(RAW, "CampusNet")
    assert [len(s.aps) for s in snaps] == [3, 2]
    assert snaps[0].meta == {"dataset": "wigle", "ssid": "CampusNet", "cell": "31.480,74.300"}
    assert {ap.ssid for s in snaps for ap in s.aps} == {"CampusNet"}


def test_credentials_from_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("WIGLE_API_NAME", raising=False)
    monkeypatch.delenv("WIGLE_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text('# comment\nWIGLE_API_NAME="AIDabc"\nWIGLE_API_KEY=secret\n')
    assert wigle.credentials(env) == ("AIDabc", "secret")
    monkeypatch.setenv("WIGLE_API_KEY", "from-env")
    assert wigle.credentials(env) == ("AIDabc", "from-env")
    monkeypatch.delenv("WIGLE_API_KEY")
    with pytest.raises(wigle.WigleError):
        wigle.credentials(tmp_path / "missing.env")


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_search_follows_pages_and_stops_on_limit(monkeypatch):
    pages = [
        {"success": True, "results": RAW[:2], "searchAfter": "100"},
        {"success": True, "results": RAW[2:4], "searchAfter": "200"},
    ]
    urls = []

    def fake_urlopen(request, timeout):
        urls.append(request.full_url)
        assert request.headers["Authorization"].startswith("Basic ")
        if len(urls) > len(pages):
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many", {}, io.BytesIO(b""))
        return FakeResponse(json.dumps(pages[len(urls) - 1]).encode())

    monkeypatch.setattr(wigle.urllib.request, "urlopen", fake_urlopen)
    results = wigle.search("CampusNet", (31.4, 31.6, 74.2, 74.4), 1000, ("name", "key"))
    assert len(results) == 4
    assert "latrange1=31.4" in urls[0] and "searchAfter" not in urls[0]
    assert "searchAfter=100" in urls[1] and "searchAfter=200" in urls[2]


def test_parse_bbox_orders_corners():
    assert wigle.parse_bbox("31.6,31.4,74.4,74.2") == (31.4, 31.6, 74.2, 74.4)


def full_ap(bssid, freq, signal):
    return APRecord(bssid=bssid, ssid="CampusNet", freq_mhz=freq, signal_dbm=signal,
                    security=("WPA2",), akm=("PSK",), beacon_interval=102,
                    capabilities=0x1431, tsf=5000, label=BENIGN)


@pytest.fixture
def lab_base():
    aps = (full_ap("02:00:00:00:01:01", 2412, -45.0), full_ap("02:00:00:00:01:02", 5180, -60.0))
    return [Snapshot(time=float(i), source="test", aps=aps, meta={"ssid": "CampusNet"}) for i in range(3)]


@pytest.mark.parametrize("scenario", synth.SCENARIOS)
def test_session_shape_and_labels(lab_base, scenario):
    snaps = synth.session("lab", "CampusNet", lab_base, scenario, 4, 3, random.Random(1), "s1")
    assert len(snaps) == 7
    assert all(s.meta["scenario"] == scenario and s.meta["learn_scans"] == 4 for s in snaps)
    learn_labels = {ap.label for s in snaps[:4] for ap in s.aps}
    assert learn_labels == {BENIGN}
    attack_labels = {ap.label for s in snaps[4:] for ap in s.aps}
    assert attack_labels == ({BENIGN, EVIL_TWIN} if scenario in synth.ATTACK_SCENARIOS else {BENIGN})


def _extra(snaps, learn_scans=4):
    base = {ap.bssid + str(ap.freq_mhz) for s in snaps[:learn_scans] for ap in s.aps}
    return [ap for ap in snaps[-1].aps if ap.bssid + str(ap.freq_mhz) not in base]


def test_scenarios_change_only_their_fields(lab_base):
    rng = random.Random(7)
    target_bssid = "02:00:00:00:01:01"  # strongest AP

    [twin] = _extra(synth.session("lab", "CampusNet", lab_base, "open_network", 4, 3, rng, "a"))
    assert twin.security == ("OPEN",) and twin.akm == ()
    assert not twin.capabilities & synth.PRIVACY_BIT
    assert twin.oui != "02:00:00" and twin.freq_mhz == 2412

    [twin] = _extra(synth.session("lab", "CampusNet", lab_base, "cloned_bssid", 4, 3, rng, "b"))
    assert twin.bssid == target_bssid and twin.freq_mhz not in (2412, 5180)
    assert twin.security == ("WPA2",) and twin.akm == ("PSK",)

    [twin] = _extra(synth.session("lab", "CampusNet", lab_base, "stronger_signal", 4, 3, rng, "c"))
    assert twin.signal_dbm > -45.0 + 10

    [new] = _extra(synth.session("lab", "CampusNet", lab_base, "benign_new_ap", 4, 3, rng, "d")) or [None]
    if new is not None:
        assert new.oui == "02:00:00" and new.label == BENIGN
        assert (new.security, new.akm, new.beacon_interval, new.capabilities) == \
            (("WPA2",), ("PSK",), 102, 0x1431)


def test_careful_and_default_attackers_both_occur(lab_base):
    rng = random.Random(0)
    beacons = Counter()
    for i in range(40):
        [twin] = _extra(synth.session("lab", "CampusNet", lab_base, "same_security", 4, 3, rng, str(i)))
        beacons[(twin.beacon_interval, twin.capabilities)] += 1
    assert set(beacons) == {(102, 0x1431), (synth.HOSTAPD_BEACON_TU, 0x0411)}


def test_twin_mirrors_missing_fields_of_wigle_base():
    snaps = wigle.to_snapshots(RAW, "CampusNet")
    sess = synth.session("w", "CampusNet", snaps[:1], "same_security", 3, 2, random.Random(3), "w")
    twin = next(ap for ap in sess[-1].aps if ap.label == EVIL_TWIN)
    assert twin.capabilities is None and twin.tsf is None and twin.akm == ()
    assert sess[0].meta["simulated_rssi"] is True
    assert all(ap.signal_dbm is not None for s in sess for ap in s.aps)


def test_generate_is_reproducible_and_counts(tmp_path, lab_base):
    src = tmp_path / "lab.jsonl"
    for s in lab_base:
        recording.append(src, s)
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    counts = synth.generate([src], a, seed=5, learn_scans=3, attack_scans=2, repeats=2)
    synth.generate([src], b, seed=5, learn_scans=3, attack_scans=2, repeats=2)
    assert a.read_text() == b.read_text()
    assert counts == {s: 2 for s in synth.SCENARIOS}
    sessions = {s.meta["session"] for s in recording.read(a)}
    assert len(sessions) == 2 * len(synth.SCENARIOS)


def test_bases_split_wigle_cells_and_drop_twins(lab_base):
    twin = full_ap("0a:11:22:33:44:55", 2412, -30.0).with_label(EVIL_TWIN)
    with_twin = [Snapshot(0.0, "t", lab_base[0].aps + (twin,), {"ssid": "CampusNet"})]
    [(origin, ssid, snaps)] = synth.bases(with_twin, None, "lab")
    assert (origin, ssid) == ("lab", "CampusNet")
    assert EVIL_TWIN not in {ap.label for ap in snaps[0].aps}

    cells = synth.bases(wigle.to_snapshots(RAW, "CampusNet"), None, "city")
    assert [o for o, _, _ in cells] == ["city@31.480,74.300", "city@31.600,74.400"]

    with pytest.raises(ValueError, match="--ssid"):
        synth.bases([Snapshot(0.0, "t", lab_base[0].aps)], None, "x")


def test_weighted_detector_on_synthetic_sessions(lab_base):
    """Sanity check: the generator produces what the detectors are meant to see."""
    rng = random.Random(11)
    outcomes = {}
    for scenario in synth.SCENARIOS:
        snaps = synth.session("lab", "CampusNet", lab_base, scenario, 4, 3, rng, scenario)
        base = baseline_mod.build(snaps[:4], "CampusNet")
        verdicts = [v for s in snaps[4:] for v in assess(DETECTORS["weighted"], s, base)]
        outcomes[scenario] = {v.level for v in verdicts if v.ap.label == EVIL_TWIN}
        assert {v.level for v in verdicts if v.ap.label == BENIGN and v.ap.bssid.startswith("02:00:00:00:01")} == {SAFE}
    for scenario in synth.ATTACK_SCENARIOS:
        assert SAFE not in outcomes[scenario], scenario


def test_area_download_groups_each_ssid_and_drops_excluded():
    raw = RAW + [
        wigle_record("02:00:00:00:05:01", 31.4800, 74.3000, ssid="CafeNet"),
        wigle_record("02:00:00:00:05:02", 31.4801, 74.3001, ssid="CafeNet"),
        wigle_record("02:00:00:00:06:01", 31.4800, 74.3000, ssid="LabNet"),
        wigle_record("02:00:00:00:06:02", 31.4800, 74.3001, ssid="LabNet"),
        wigle_record("02:00:00:00:07:01", 31.4800, 74.3000, ssid=""),
        wigle_record("02:00:00:00:07:02", 31.4800, 74.3001, ssid=""),
    ]
    snaps = wigle.to_snapshots(raw, None, exclude=frozenset({"LabNet"}))
    assert [(s.meta["ssid"], len(s.aps)) for s in snaps] == [("CafeNet", 2), ("CampusNet", 3), ("CampusNet", 2)]
    assert all({a.ssid for a in s.aps} == {s.meta["ssid"]} for s in snaps)


def test_search_optional_filters(monkeypatch):
    urls = []

    def fake_urlopen(request, timeout):
        urls.append(request.full_url)
        return FakeResponse(json.dumps({"success": True, "results": RAW[:1]}).encode())

    monkeypatch.setattr(wigle.urllib.request, "urlopen", fake_urlopen)
    wigle.search(None, (31.4, 31.6, 74.2, 74.4), 10, ("n", "k"), encryption="wpa3", since="20230101")
    assert "ssid=" not in urls[0]
    assert "encryption=wpa3" in urls[0] and "lastupdt=20230101" in urls[0]
    with pytest.raises(SystemExit):
        wigle.main(["download", "--bbox", "1,2,3,4", "--since", "2023", "-o", "x.json"])
