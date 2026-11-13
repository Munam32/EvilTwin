from pathlib import Path

import pytest

from twinwatch.scan import iw, nmcli

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def iw_aps():
    aps = iw.parse((FIXTURES / "iw_scan.txt").read_text(), max_age_ms=30_000)
    return {ap.bssid: ap for ap in aps}


def test_iw_wpa2_psk(iw_aps):
    ap = iw_aps["02:00:00:00:01:01"]
    assert ap.ssid == "CampusNet"
    assert (ap.freq_mhz, ap.channel, ap.band) == (2412, 1, "2.4")
    assert ap.signal_dbm == -42.0
    assert ap.security == ("WPA2",)
    assert ap.akm == ("PSK",)
    assert ap.pairwise == ("CCMP",)
    assert ap.beacon_interval == 100
    assert ap.capabilities == 0x1411
    assert ap.tsf == 123456789012
    assert ap.oui == "02:00:00"


def test_iw_wpa3_transition_on_5ghz(iw_aps):
    ap = iw_aps["02:00:00:00:01:02"]
    assert ap.security == ("WPA2", "WPA3")
    assert ap.akm == ("PSK", "SAE")
    assert (ap.channel, ap.band) == (36, "5")
    assert ap.security_rank == 4


def test_iw_open_network(iw_aps):
    ap = iw_aps["02:00:00:00:02:01"]
    assert ap.security == ("OPEN",)
    assert ap.security_rank == 0
    assert ap.beacon_interval == 102


def test_iw_mixed_wpa_and_escaped_ssid(iw_aps):
    ap = iw_aps["02:00:00:00:03:01"]
    assert ap.ssid == "Legacyé"
    assert ap.security == ("WPA", "WPA2")
    assert ap.pairwise == ("CCMP", "TKIP")


def test_iw_wep_from_privacy_bit(iw_aps):
    assert iw_aps["02:00:00:00:04:01"].security == ("WEP",)


def test_iw_enterprise(iw_aps):
    ap = iw_aps["02:00:00:00:05:01"]
    assert ap.security == ("WPA2",)
    assert ap.akm == ("EAP",)


def test_iw_drops_stale_entries(iw_aps):
    assert "02:00:00:00:06:01" not in iw_aps
    all_aps = iw.parse((FIXTURES / "iw_scan.txt").read_text())
    assert len(all_aps) == len(iw_aps) + 1


def test_nmcli_parse():
    aps = {ap.bssid: ap for ap in nmcli.parse((FIXTURES / "nmcli_scan.txt").read_text())}
    assert len(aps) == 5

    ap = aps["02:00:00:00:01:01"]
    assert (ap.ssid, ap.channel, ap.security, ap.akm) == ("CampusNet", 1, ("WPA2",), ("PSK",))
    assert ap.signal_dbm == pytest.approx(-60.5)
    assert ap.beacon_interval is None

    assert aps["02:00:00:00:01:02"].security == ("WPA2", "WPA3")
    assert aps["02:00:00:00:02:01"].security == ("OPEN",)
    assert aps["02:00:00:00:03:01"].ssid == "Cafe:Guest"
    assert aps["02:00:00:00:03:01"].security == ("WPA", "WPA2")
    assert aps["02:00:00:00:05:01"].akm == ("EAP",)


def test_parsers_agree_on_shared_fields():
    by_iw = {ap.bssid: ap for ap in iw.parse((FIXTURES / "iw_scan.txt").read_text())}
    for ap in nmcli.parse((FIXTURES / "nmcli_scan.txt").read_text()):
        if ap.ssid != "CampusNet":
            continue
        other = by_iw[ap.bssid]
        assert (ap.freq_mhz, ap.security) == (other.freq_mhz, other.security)


def test_split_terse_escapes():
    assert nmcli.split_terse(r"a\:b:c\\d:") == ["a:b", "c\\d", ""]
