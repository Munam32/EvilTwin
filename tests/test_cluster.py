import pytest

from twinwatch import baseline as baseline_mod
from twinwatch import cluster, recording
from twinwatch.features import extract, fired
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot

SSID = "HomeNet"
ROUTER = "02:00:00:00:01:01"    # WPA2, capability 0x1431
EXTENDER = "02:00:aa:00:02:01"  # other vendor, WPA/WPA2, capability 0x0431


def ap(bssid, freq=2457, security=("WPA2",), akm=("PSK",), beacon=100, caps=0x1431, label=None):
    return APRecord(bssid=bssid, ssid=SSID, freq_mhz=freq, signal_dbm=-50.0, security=security,
                    akm=akm, beacon_interval=beacon, capabilities=caps, label=label)


HOME = (ap(ROUTER), ap(EXTENDER, security=("WPA", "WPA2"), caps=0x0431))


@pytest.fixture
def home_baseline():
    return baseline_mod.build([Snapshot(float(i), "test", HOME) for i in range(4)], SSID)


def fp(record):
    return cluster.fingerprint(record)


def test_distance_components():
    router = fp(ap(ROUTER))
    assert cluster.distance(router, router) == 0.0
    assert cluster.distance(router, fp(ap("0a:11:22:33:44:55"))) == 0.25
    assert cluster.distance(router, fp(ap(ROUTER, beacon=102))) == 0.25
    one_bit = cluster.distance(router, fp(ap(ROUTER, caps=0x0431)))
    assert one_bit == pytest.approx((1 / 5) / 4)
    open_twin = cluster.distance(router, fp(ap("0a:11:22:33:44:55", security=("OPEN",), akm=(), caps=0x0401)))
    assert open_twin > 0.5


def test_unknown_attributes_are_skipped():
    wigle_like = fp(ap(ROUTER, beacon=None, caps=None))
    other_vendor = fp(ap("0a:11:22:33:44:55", beacon=None, caps=None))
    assert cluster.distance(wigle_like, other_vendor) == 0.5
    assert cluster.distance(wigle_like, fp(ap(ROUTER))) == 0.0


def test_unlike_trusted_devices_form_separate_clusters(home_baseline):
    clusters = cluster.NetworkClusters(home_baseline.aps)
    assert clusters.n_clusters == 2
    assert clusters.core == [0, 1]
    for known in HOME:
        assert clusters.assign(known)[0] != -1


def test_assign_new_aps(home_baseline):
    clusters = cluster.NetworkClusters(home_baseline.aps)
    same_model = ap("02:00:00:00:01:09", freq=5180)
    assert clusters.assign(same_model) == (clusters.labels[0], 0.0)
    careful_twin = ap("0a:11:22:33:44:55")
    assert clusters.assign(careful_twin)[0] == -1
    cloned = ap(ROUTER, freq=2412, caps=0x0411)
    assert clusters.assign(cloned)[0] != -1


def test_cluster_signals_in_features(home_baseline):
    twin = extract(ap("0a:11:22:33:44:55", security=("OPEN",), akm=(), caps=0x0401), home_baseline)
    assert twin["cluster_outlier"] == 1.0 and twin["cluster_distance"] > 0.5
    assert "cluster_outlier" in fired(twin) and "cluster_distance" not in fired(twin)
    known = extract(HOME[1], home_baseline)
    assert known["cluster_outlier"] == 0.0 and known["cluster_distance"] == 0.0


def test_clusters_cached_per_baseline(home_baseline):
    assert cluster.clusters_for(home_baseline) is cluster.clusters_for(home_baseline)


def test_tune_and_recommend(home_baseline):
    sessions = [(home_baseline, [ap("02:00:00:00:01:09", label=BENIGN),
                                 ap("0a:11:22:33:44:55", label=EVIL_TWIN),
                                 ap("0a:11:22:33:44:56", security=("OPEN",), akm=(), caps=0x0401,
                                    label=EVIL_TWIN)])]
    rows = cluster.tune(sessions, [0.1, 0.2, 0.3, 0.6])
    assert [r["twin_outlier"] for r in rows] == [1.0, 1.0, 0.5, 0.0]
    assert all(r["benign_outlier"] == 0.0 for r in rows)
    assert cluster.recommend(rows, max_benign_outlier=0.05)["eps"] == 0.2
    assert cluster.recommend(rows, max_benign_outlier=-1) is None


def test_sessions_split_by_session_and_ssid():
    snaps = [Snapshot(0.0, "t", HOME, {"ssid": "A"}), Snapshot(1.0, "t", HOME, {"ssid": "B"}),
             Snapshot(2.0, "t", HOME, {"ssid": "A"}),
             Snapshot(3.0, "t", HOME, {"ssid": "A", "session": "s1"})]
    groups = recording.sessions(snaps, "file")
    assert {k: [s.time for s in v] for k, v in groups.items()} == {
        ("file", "A"): [0.0, 2.0], ("file", "B"): [1.0], ("s1", "A"): [3.0]}
