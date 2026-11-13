import csv
import shutil

import pytest

from twinwatch import baseline as baseline_mod
from twinwatch import recording
from twinwatch.cli import main as cli_main
from twinwatch.datasets import awid3
from twinwatch.detectors import DETECTORS, LIKELY, SAFE, assess
from twinwatch.model import BENIGN, EVIL_TWIN

REAL = "02:00:00:00:01:01"
MIXED = "02:00:00:00:02:01"
ROGUE = "02:00:00:00:03:01"
TWIN = "0a:11:22:33:44:55"

# Column order and extra columns differ from tshark's, as in a dataset export.
COLUMNS = ["frame.number", "frame.time_epoch", "wlan.fc.type_subtype", "wlan.bssid", "wlan.ssid",
           "radiotap.dbm_antsignal", "radiotap.channel.freq", "wlan.fixed.beacon",
           "wlan.fixed.capabilities", "wlan.fixed.capabilities.privacy", "wlan.fixed.timestamp",
           "wlan.rsn.akms.type", "wlan.rsn.pcs.type", "wlan.wfa.ie.wpa.akms.type",
           "wlan.wfa.ie.wpa.ucs.type", "Label"]


def frame(t, bssid, subtype="0x0008", ssid="CampusNet", freq="2412", signal="-40,-42",
          beacon="100", caps="0x1411", privacy="1", rsn_akm="2", rsn_pcs="4",
          wpa_akm="", wpa_ucs="", label="Normal"):
    return {"frame.number": "0", "frame.time_epoch": f"{1600000000 + t:.6f}",
            "wlan.fc.type_subtype": subtype, "wlan.bssid": bssid, "wlan.ssid": ssid,
            "radiotap.dbm_antsignal": signal, "radiotap.channel.freq": freq,
            "wlan.fixed.beacon": beacon, "wlan.fixed.capabilities": caps,
            "wlan.fixed.capabilities.privacy": privacy, "wlan.fixed.timestamp": str(1000 + t * 102400),
            "wlan.rsn.akms.type": rsn_akm, "wlan.rsn.pcs.type": rsn_pcs,
            "wlan.wfa.ie.wpa.akms.type": wpa_akm, "wlan.wfa.ie.wpa.ucs.type": wpa_ucs, "Label": label}


def capture_rows():
    rows = []
    for t in range(26):
        rows.append(frame(t, REAL))
        if t % 5 == 0:
            rows.append(frame(t + 0.5, MIXED, subtype="0x0005", freq="2437", signal="-60",
                              wpa_akm="2", wpa_ucs="2;4", rsn_pcs="2;4"))
        if t >= 15:
            rows.append(frame(t + 0.2, TWIN, signal="-30", caps="0x0401", privacy="0",
                              rsn_akm="", rsn_pcs="", label="Evil_Twin"))
    rows.append(frame(3.1, ROGUE, ssid="Other", label="RogueAP"))
    rows.append(frame(4.0, "ff:ff:ff:ff:ff:ff", subtype="0x0004", label="Normal"))
    rows.append(frame(5.0, REAL, subtype="0x000c", label="Deauth"))
    return sorted(rows, key=lambda r: float(r["frame.time_epoch"]))


@pytest.fixture
def capture_csv(tmp_path):
    path = tmp_path / "Evil_Twin_1.csv"
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(capture_rows())
    return path


def test_beacon_row_to_record():
    t, rec = awid3.frame_to_record(frame(0, REAL))
    assert t == 1600000000.0
    assert (rec.bssid, rec.ssid, rec.freq_mhz, rec.signal_dbm) == (REAL, "CampusNet", 2412, -40.0)
    assert (rec.security, rec.akm, rec.pairwise) == (("WPA2",), ("PSK",), ("CCMP",))
    assert (rec.beacon_interval, rec.capabilities, rec.tsf, rec.label) == (100, 0x1411, 1000, BENIGN)


@pytest.mark.parametrize("rsn_akm,wpa_akm,privacy,security", [
    ("2", "", "1", ("WPA2",)),
    ("2;8", "", "1", ("WPA2", "WPA3")),
    ("8", "", "1", ("WPA3",)),
    ("12", "", "1", ("WPA3",)),
    ("1", "", "1", ("WPA2",)),
    ("2", "2", "1", ("WPA", "WPA2")),
    ("", "", "1", ("WEP",)),
    ("", "", "True", ("WEP",)),
    ("", "", "0", ("OPEN",)),
])
def test_security_from_akm_codes(rsn_akm, wpa_akm, privacy, security):
    row = frame(0, REAL, rsn_akm=rsn_akm, rsn_pcs="4" if rsn_akm else "", wpa_akm=wpa_akm,
                caps="0x0401", privacy=privacy)
    assert awid3.frame_to_record(row)[1].security == security


def test_non_beacon_frames_skipped():
    assert awid3.frame_to_record(frame(0, REAL, subtype="0x0004")) is None
    assert awid3.frame_to_record(frame(0, REAL, subtype="12")) is None
    assert awid3.frame_to_record(frame(0, REAL, freq="")) is None
    assert awid3.frame_to_record(frame(0, REAL, subtype="5")) is not None


@pytest.mark.parametrize("raw,label", [
    ("Normal", BENIGN), ("normal", BENIGN), ("Evil_Twin", EVIL_TWIN), ("Evil Twin", EVIL_TWIN),
    ("evil-twin", EVIL_TWIN), ("Deauth", None), ("RogueAP", None), ("", None), (None, None),
])
def test_map_label(raw, label):
    assert awid3.map_label(raw) == label


@pytest.mark.parametrize("raw,ssid", [
    ("CampusNet", "CampusNet"), ("43616d7075734e6574", "CampusNet"), ("cafe", "cafe"), ("", ""),
])
def test_decode_ssid(raw, ssid):
    assert awid3._decode_ssid(raw) == ssid


def test_windows_group_frames_and_label(capture_csv):
    snaps = list(awid3.windows(awid3.read_csv(capture_csv), 10.0, {"dataset": "awid3"}))
    assert [s.time for s in snaps] == [1600000000.0, 1600000010.0, 1600000020.0]

    first = {ap.bssid: ap for ap in snaps[0].aps}
    assert set(first) == {REAL, MIXED, ROGUE}
    assert first[REAL].signal_dbm == -40.0 and first[REAL].tsf == 1000 + 9 * 102400
    assert first[MIXED].security == ("WPA", "WPA2") and first[MIXED].pairwise == ("CCMP", "TKIP")
    assert first[ROGUE].label is None

    second = {ap.bssid: ap for ap in snaps[1].aps}
    assert second[TWIN].label == EVIL_TWIN and second[TWIN].security == ("OPEN",)
    assert second[REAL].label == BENIGN


def test_windows_skip_empty_gaps():
    rows = [frame(0, REAL), frame(35, REAL)]
    snaps = list(awid3.windows(rows, 10.0, {}))
    assert [s.time - 1600000000 for s in snaps] == [0.0, 30.0]


def test_convert_writes_recording(capture_csv, tmp_path):
    out = tmp_path / "out" / "et.jsonl"
    out.parent.mkdir()
    out.write_text("stale\n")
    counts = awid3.convert(capture_csv, out)
    snaps = list(recording.read(out))
    assert len(snaps) == counts["snapshots"] == 3
    assert snaps[0].meta == {"dataset": "awid3", "file": "Evil_Twin_1.csv"}
    assert counts[EVIL_TWIN] == 2 and counts["unlabelled"] == 1


def test_missing_columns_named(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("frame.time_epoch,wlan.bssid\n1,02:00:00:00:00:01\n")
    with pytest.raises(awid3.AwidError, match="wlan.fc.type_subtype.*wlan.ssid.*radiotap.channel.freq"):
        list(awid3.read_csv(path))


def test_converted_capture_feeds_detectors(capture_csv, tmp_path, capsys):
    out = tmp_path / "et.jsonl"
    awid3.convert(capture_csv, out)
    snaps = list(recording.read(out))
    base = baseline_mod.build(snaps[:1], "CampusNet")

    levels = {(v.ap.label, v.level) for s in snaps[1:]
              for v in assess(DETECTORS["weighted"], s, base)}
    assert levels == {(BENIGN, SAFE), (EVIL_TWIN, LIKELY)}

    cli_main(["replay", str(out), "--ssid", "CampusNet", "--learn-scans", "1"])
    assert "evil_twin" in capsys.readouterr().out


@pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")
def test_pcap_through_tshark(tmp_path):
    scapy = pytest.importorskip("scapy.all")
    frames = []
    for i in range(12):
        dot11 = scapy.Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=REAL, addr3=REAL)
        beacon = scapy.Dot11Beacon(timestamp=1000 + i, beacon_interval=100, cap="ESS+privacy")
        rsn = scapy.Dot11EltRSN(akm_suites=[scapy.AKMSuite(suite=2)],
                                pairwise_cipher_suites=[scapy.RSNCipherSuite(cipher=4)])
        pkt = (scapy.RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2412, dBm_AntSignal=-45)
               / dot11 / beacon / scapy.Dot11Elt(ID="SSID", info=b"CampusNet") / rsn)
        pkt.time = 1600000000 + i
        frames.append(pkt)
    pcap = tmp_path / "beacons.pcap"
    scapy.wrpcap(str(pcap), frames)

    out = tmp_path / "pcap.jsonl"
    counts = awid3.convert(pcap, out, window_s=10.0)
    snaps = list(recording.read(out))
    assert counts["snapshots"] == 2
    ap = snaps[0].aps[0]
    assert (ap.bssid, ap.ssid, ap.freq_mhz, ap.signal_dbm) == (REAL, "CampusNet", 2412, -45.0)
    assert (ap.security, ap.akm, ap.beacon_interval) == (("WPA2",), ("PSK",), 100)
    assert ap.label is None
