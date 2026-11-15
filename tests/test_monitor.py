import random

import pytest

scapy = pytest.importorskip("scapy.all")

from twinwatch import baseline as baseline_mod  # noqa: E402
from twinwatch import beacons  # noqa: E402
from twinwatch.datasets import synth  # noqa: E402
from twinwatch.features import extract, fired  # noqa: E402
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot  # noqa: E402
from twinwatch.scan import ScanError, monitor  # noqa: E402
from twinwatch.scan import scan as run_scan  # noqa: E402

REAL = "02:00:00:00:01:01"


def beacon(bssid=REAL, ssid=b"HomeNet", freq=2412, signal=-45, tsf=1000, cap="ESS+privacy",
           rsn_akm=(2,), wpa_akm=None, probe=False, interval=100):
    dot11 = scapy.Dot11(type=0, subtype=5 if probe else 8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    body = (scapy.Dot11ProbeResp if probe else scapy.Dot11Beacon)(timestamp=tsf, beacon_interval=interval, cap=cap)
    pkt = (scapy.RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=freq, dBm_AntSignal=signal)
           / dot11 / body / scapy.Dot11Elt(ID="SSID", info=ssid))
    if rsn_akm is not None:
        pkt /= scapy.Dot11EltRSN(akm_suites=[scapy.AKMSuite(suite=c) for c in rsn_akm],
                                 pairwise_cipher_suites=[scapy.RSNCipherSuite(cipher=4)])
    if wpa_akm is not None:
        pkt /= scapy.Dot11EltMicrosoftWPA(akm_suites=[scapy.AKMSuite(suite=c) for c in wpa_akm],
                                          pairwise_cipher_suites=[scapy.RSNCipherSuite(cipher=2)])
    return scapy.RadioTap(bytes(pkt))  # dissected from bytes, as a capture would be


def test_beacon_to_record():
    rec = monitor.frame_to_record(beacon())
    assert (rec.bssid, rec.ssid, rec.freq_mhz, rec.signal_dbm) == (REAL, "HomeNet", 2412, -45.0)
    assert (rec.security, rec.akm, rec.pairwise) == (("WPA2",), ("PSK",), ("CCMP",))
    assert (rec.beacon_interval, rec.tsf, rec.capabilities & 0x0010) == (100, 1000, 0x0010)
    assert rec.tsf_backwards is None  # known only after merging frames


@pytest.mark.parametrize("kwargs,security,akm", [
    ({"rsn_akm": (2, 8)}, ("WPA2", "WPA3"), ("PSK", "SAE")),
    ({"rsn_akm": (2,), "wpa_akm": (2,)}, ("WPA", "WPA2"), ("PSK",)),
    ({"rsn_akm": None, "cap": "ESS"}, ("OPEN",), ()),
    ({"rsn_akm": None}, ("WEP",), ()),
    ({"rsn_akm": (2,), "probe": True}, ("WPA2",), ("PSK",)),
])
def test_security_variants(kwargs, security, akm):
    rec = monitor.frame_to_record(beacon(**kwargs))
    assert (rec.security, rec.akm) == (security, akm)


def test_other_frames_ignored():
    probe_request = scapy.RadioTap() / scapy.Dot11(type=0, subtype=4) / scapy.Dot11ProbeReq()
    assert monitor.frame_to_record(scapy.RadioTap(bytes(probe_request))) is None


def test_frequency_falls_back_to_tuned_channel():
    pkt = scapy.RadioTap() / scapy.Dot11(type=0, subtype=8, addr2=REAL, addr3=REAL) / scapy.Dot11Beacon()
    pkt = scapy.RadioTap(bytes(pkt / scapy.Dot11Elt(ID="SSID", info=b"HomeNet")))
    assert monitor.frame_to_record(pkt, tuned_freq=2437).freq_mhz == 2437
    assert monitor.frame_to_record(pkt) is None


def test_tsf_backwards_counts_decreases():
    frames = [APRecord(REAL, "HomeNet", 2412, -40.0, ("WPA2",), tsf=t) for t in (10, 20, 15, 30, 25)]
    assert beacons.tsf_backwards(frames) == 2
    assert beacons.tsf_backwards(frames[:2]) == 0
    assert beacons.tsf_backwards([APRecord(REAL, "HomeNet", 2412, -40.0, ("WPA2",))]) is None


def test_capture_hops_and_spots_same_channel_clone():
    """Real AP and a clone with the same BSSID on channel 1: their TSFs interleave."""
    on_air = {
        2412: [beacon(tsf=1_000_000), beacon(tsf=5_000, signal=-30),
               beacon(tsf=1_102_400), beacon(tsf=107_400, signal=-30)],
        2437: [beacon("02:00:00:00:02:01", freq=2437, tsf=t) for t in (1, 2, 3)],
    }
    tuned = []

    def tune(interface, freq):
        tuned.append(freq)

    def sniff(iface, timeout, store):
        return on_air.get(tuned[-1], [])

    snap = monitor.capture("mon0", freqs=[2437, 2412, 5180], dwell=0.1, sniff=sniff, tune=tune)
    assert tuned == [2412, 2437, 5180]
    assert snap.meta == {"monitor_freqs": [2412, 2437, 5180]}
    aps = {ap.bssid: ap for ap in snap.aps}
    assert snap.source == "monitor"
    assert aps[REAL].tsf_backwards == 2 and aps[REAL].signal_dbm == pytest.approx(-37.5)
    assert aps["02:00:00:00:02:01"].tsf_backwards == 0


def test_check_interface(monkeypatch, tmp_path):
    monkeypatch.setattr(monitor.os, "geteuid", lambda: 1000)
    with pytest.raises(monitor.MonitorError, match="root"):
        monitor.check_interface("lo")
    monkeypatch.setattr(monitor.os, "geteuid", lambda: 0)
    with pytest.raises(monitor.MonitorError, match="not in monitor mode"):
        monitor.check_interface("lo")
    with pytest.raises(monitor.MonitorError, match="no interface"):
        monitor.check_interface("does-not-exist0")


def test_scan_backend_reports_monitor_errors(monkeypatch):
    monkeypatch.setattr(monitor.os, "geteuid", lambda: 1000)
    monkeypatch.setattr("twinwatch.scan.shutil.which", lambda tool: "/usr/sbin/" + tool)
    with pytest.raises(ScanError, match="root"):
        run_scan("mon0", "monitor")


def ap(tsf_backwards, label=BENIGN, bssid=REAL):
    return APRecord(bssid, "HomeNet", 2412, -45.0, ("WPA2",), ("PSK",), beacon_interval=100,
                    capabilities=0x1431, tsf=1000, tsf_backwards=tsf_backwards, label=label)


def test_tsf_anomaly_signal():
    base = baseline_mod.build([Snapshot(0.0, "monitor", (ap(0),))], "HomeNet")
    clone = extract(ap(3, EVIL_TWIN), base)
    assert clone["tsf_anomaly"] == 1.0 and "tsf_anomaly" in fired(clone)
    assert not clone["new_bssid"] and not clone["channel_jump"]
    assert extract(ap(0), base)["tsf_anomaly"] == 0.0
    assert extract(ap(None), base)["tsf_anomaly"] == 0.0


def test_same_channel_clone_scenario_only_with_beacon_tsf(tmp_path):
    monitor_base = [Snapshot(float(i), "monitor", (ap(0), ap(0, bssid="02:00:00:00:01:02")),
                             {"ssid": "HomeNet"}) for i in range(3)]
    snaps = synth.session("m", "HomeNet", monitor_base, "cloned_same_channel", 4, 3, random.Random(0), "s")
    assert {a.label for s in snaps[:4] for a in s.aps} == {BENIGN}
    twins = [a for s in snaps[4:] for a in s.aps if a.label == EVIL_TWIN]
    assert twins and all(a.tsf_backwards >= 1 and a.bssid == twins[0].bssid for a in twins)
    assert all(len(s.aps) <= 2 for s in snaps)  # merged into the real AP, no extra entry

    scan_base = [Snapshot(0.0, "live-iw", (ap(None),), {"ssid": "HomeNet"})]
    with pytest.raises(ValueError, match="per-beacon TSF"):
        synth.session("i", "HomeNet", scan_base, "cloned_same_channel", 4, 3, random.Random(0), "s")


IW_DEV = """phy#0
\tInterface mon0
\t\tifindex 4
\t\ttype monitor
\tInterface wlp4s0
\t\tifindex 3
\t\tssid HomeNet_5G
\t\ttype managed
\t\tchannel 157 (5785 MHz), width: 80 MHz, center1: 5775 MHz
phy#1
\tInterface wlan1
\t\ttype monitor
"""


def test_current_freq_reads_sibling_interface():
    assert monitor.current_freq("mon0", IW_DEV) == 5785
    assert monitor.current_freq("wlp4s0", IW_DEV) == 5785
    assert monitor.current_freq("wlan1", IW_DEV) is None
    assert monitor.current_freq("missing0", IW_DEV) is None


def busy(interface, freq):
    raise monitor.ChannelBusy("command failed: Device or resource busy (-16)")


def test_capture_stays_on_current_channel_when_busy():
    calls = []

    def sniff(iface, timeout, store):
        calls.append(timeout)
        return [beacon(freq=5785, tsf=t) for t in (1, 2)]

    snap = monitor.capture("mon0", freqs=[2412, 2437, 5785], dwell=0.5, sniff=sniff, tune=busy,
                           locate=lambda iface: 5785)
    assert calls == [1.5]  # whole scan time spent on the one channel
    assert snap.meta == {"monitor_freqs": [5785]}
    assert [ap.freq_mhz for ap in snap.aps] == [5785]


def test_capture_busy_with_unknown_channel_fails_clearly():
    with pytest.raises(monitor.MonitorError, match="second adapter"):
        monitor.capture("mon0", sniff=lambda **kw: [], tune=busy, locate=lambda iface: None)


def test_other_tuning_errors_propagate(monkeypatch):
    class Proc:
        returncode, stderr = 1, "command failed: Invalid argument (-22)"

    monkeypatch.setattr(monitor.subprocess, "run", lambda *a, **kw: Proc())
    with pytest.raises(monitor.MonitorError) as err:
        monitor.set_channel_checked("mon0", 2412)
    assert not isinstance(err.value, monitor.ChannelBusy)
    Proc.stderr = "command failed: Device or resource busy (-16)"
    with pytest.raises(monitor.ChannelBusy):
        monitor.set_channel_checked("mon0", 2412)


def fake_sysfs(tmp_path, monkeypatch, iface_type, flags):
    dev = tmp_path / "mon0"
    dev.mkdir()
    (dev / "type").write_text(f"{iface_type}\n")
    (dev / "flags").write_text(f"{flags}\n")
    monkeypatch.setattr(monitor, "SYS_NET", tmp_path)
    monkeypatch.setattr(monitor.os, "geteuid", lambda: 0)


def test_check_interface_down(tmp_path, monkeypatch):
    fake_sysfs(tmp_path, monkeypatch, 803, "0x1002")
    with pytest.raises(monitor.MonitorError, match="mon0 is down.*ip link set mon0 up"):
        monitor.check_interface("mon0")


def test_check_interface_ok(tmp_path, monkeypatch):
    fake_sysfs(tmp_path, monkeypatch, 803, "0x1003")
    monitor.check_interface("mon0")


def test_capture_os_error_becomes_monitor_error():
    def sniff(**kwargs):
        raise OSError(100, "Network is down")

    with pytest.raises(monitor.MonitorError, match="capture on mon0 failed: Network is down"):
        monitor.capture("mon0", freqs=[2412], sniff=sniff, tune=lambda i, f: None)


def test_capture_registers_radiotap_before_sniffing():
    """Run in a fresh interpreter: elsewhere the test module already imported the layers."""
    import subprocess
    import sys

    code = (
        "from scapy.config import conf\n"
        "import scapy.sendrecv\n"
        "from twinwatch.scan import monitor\n"
        "seen = []\n"
        "def sniff(**kw):\n"
        "    seen.append(conf.l2types.get(803))\n"
        "    return []\n"
        "import scapy.sendrecv as s; s.sniff = sniff\n"
        "monitor.capture('mon0', freqs=[2412], tune=lambda i, f: None)\n"
        "print(seen[0].__name__)\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "RadioTap"
