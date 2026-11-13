import pytest

from twinwatch import recording
from twinwatch.cli import label_snapshot
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot, channel_from_freq


def ap(bssid, ssid="CampusNet", freq=2412, **kw):
    return APRecord(bssid=bssid, ssid=ssid, freq_mhz=freq, signal_dbm=-50.0,
                    security=kw.pop("security", ("WPA2",)), **kw)


@pytest.mark.parametrize("freq,channel", [(2412, 1), (2484, 14), (5180, 36), (5745, 149), (5955, 1)])
def test_channel_from_freq(freq, channel):
    assert channel_from_freq(freq) == channel


def test_bssid_is_lowercased():
    assert ap("AA:BB:CC:00:00:01").bssid == "aa:bb:cc:00:00:01"


def test_invalid_security_rejected():
    with pytest.raises(ValueError):
        ap("02:00:00:00:00:01", security=("WPA9",))
    with pytest.raises(ValueError):
        ap("02:00:00:00:00:01", security=())


def test_recording_round_trip(tmp_path):
    path = tmp_path / "session.jsonl"
    snaps = [
        Snapshot(time=1.0, source="test", meta={"scenario": "open"},
                 aps=(ap("02:00:00:00:00:01", tsf=5, beacon_interval=100),)),
        Snapshot(time=2.0, source="test", aps=(ap("02:00:00:00:00:02", label=EVIL_TWIN),)),
    ]
    for s in snaps:
        recording.append(path, s)
    assert list(recording.read(path)) == snaps


def test_recording_reports_bad_line(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"time": 1}\n')
    with pytest.raises(ValueError, match="bad.jsonl:1"):
        list(recording.read(path))


def test_label_snapshot_by_bssid_and_freq():
    real = ap("02:00:00:00:00:01", freq=2412)
    clone = ap("02:00:00:00:00:01", freq=2462)
    other_ssid = ap("02:00:00:00:00:09", ssid="Neighbour")
    snap = Snapshot(time=0.0, source="test", aps=(real, clone, other_ssid))

    labelled = label_snapshot(snap, "CampusNet", ["02:00:00:00:00:01@2462"])

    assert [a.label for a in labelled.aps] == [BENIGN, EVIL_TWIN, None]
