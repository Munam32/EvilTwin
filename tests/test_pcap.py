import argparse

import pytest

scapy = pytest.importorskip("scapy.all")

from test_monitor import REAL, beacon  # noqa: E402

from twinwatch import recording  # noqa: E402
from twinwatch.datasets import pcap  # noqa: E402
from twinwatch.model import BENIGN, EVIL_TWIN  # noqa: E402


def write_capture(path, twin_at=range(30, 60)):
    """Real AP every second for 60 s; during `twin_at` a hidden-SSID BSSID clone on the same channel."""
    pkts = []
    for t in range(60):
        real = beacon(tsf=10_000_000 + t * 1_000_000)
        real.time = 1000.0 + t
        pkts.append(real)
        if t in twin_at:
            twin = beacon(ssid=b"", tsf=5_000 + t * 1_000, interval=16, cap="ESS+privacy+short-slot")
            twin.time = 1000.5 + t
            pkts.append(twin)
    other = beacon(bssid="02:00:00:00:07:07", ssid=b"OtherNet")
    lookalike = beacon(bssid="02:00:00:00:09:09", ssid=b" HOMENET")
    lookalike.time = 1050.0
    pkts.append(lookalike)
    other.time = 1001.0
    hidden = beacon(bssid="02:00:00:00:08:08", ssid=b"")  # hidden AP never named HomeNet
    hidden.time = 1001.2
    pkts[2:2] = [other, hidden]
    scapy.wrpcap(str(path), pkts)


def test_rules_parse():
    assert pcap.parse_rule("capabilities=0x0411") == ("capabilities", 0x0411)
    assert pcap.parse_rule("bssid=02:AA:00:00:00:01") == ("bssid", "02:aa:00:00:00:01")
    for bad in ("tsf=1", "beacon_interval", "beacon_interval=x"):
        with pytest.raises(argparse.ArgumentTypeError):
            pcap.parse_rule(bad)


def test_cloned_bssid_capture_is_windowed_and_labelled(tmp_path):
    src, out = tmp_path / "cap.pcap", tmp_path / "cap.jsonl"
    write_capture(src)
    counts = pcap.convert(src, out, "HomeNet", [("beacon_interval", 16)], dataset="wpa3_attacks", learn_scans=3)
    snaps = list(recording.read(out))
    assert counts["snapshots"] == len(snaps) == 6 and counts["reordered"] == 0
    assert all(s.meta == {"dataset": "wpa3_attacks", "file": "cap.pcap", "ssid": "HomeNet", "learn_scans": 3}
               for s in snaps)
    assert all(s.aps[0].bssid == REAL for s in snaps)  # OtherNet dropped, clone merged
    assert [len(s.aps) for s in snaps] == [1, 1, 1, 1, 1, 2]  # lookalike kept
    before, after = snaps[:3], snaps[3:]
    assert {s.aps[0].label for s in before} == {BENIGN} and {s.aps[0].tsf_backwards for s in before} == {0}
    assert {s.aps[0].label for s in after} == {EVIL_TWIN}
    assert all(s.aps[0].tsf_backwards > 0 for s in after)


def test_without_rules_everything_is_benign(tmp_path):
    src, out = tmp_path / "cap.pcap", tmp_path / "cap.jsonl"
    write_capture(src)
    counts = pcap.convert(src, out, "HomeNet", [])
    assert counts[EVIL_TWIN] == 0 and counts["reordered"] == 0


def test_twin_from_the_start_moves_clean_windows_first(tmp_path):
    src, out = tmp_path / "cap.pcap", tmp_path / "cap.jsonl"
    write_capture(src)
    write_capture(src, twin_at=range(0, 20))  # attack first, then 4 clean windows
    rules = [("beacon_interval", 16)]
    with pytest.raises(pcap.PcapError, match="only 4 twin-free windows; need 5"):
        pcap.convert(src, out, "HomeNet", rules, learn_scans=5)
    counts = pcap.convert(src, out, "HomeNet", rules, learn_scans=4, scenario="cloned_same_channel")
    snaps = list(recording.read(out))
    assert counts["reordered"] == 1 and all(s.meta["reordered"] for s in snaps)
    assert {s.meta["scenario"] for s in snaps} == {"cloned_same_channel"}
    assert [any(a.label == EVIL_TWIN for a in s.aps) for s in snaps] == [False] * 4 + [True] * 2
    assert [s.time for s in snaps] == [1000.0 + 10 * i for i in range(6)]
