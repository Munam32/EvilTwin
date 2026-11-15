
import joblib
import pytest

from twinwatch import baseline as baseline_mod
from twinwatch import recording
from twinwatch.datasets import synth
from twinwatch.detectors import LIKELY, SAFE, assess, make_scorer
from twinwatch.detectors.ml import MLScorer, ModelError
from twinwatch.evaluation import train
from twinwatch.features import SIGNALS
from twinwatch.model import BENIGN, EVIL_TWIN, APRecord, Snapshot


def ap(bssid, ssid, freq, caps, security=("WPA2",)):
    return APRecord(bssid=bssid, ssid=ssid, freq_mhz=freq, signal_dbm=-50.0, security=security,
                    akm=("PSK",), beacon_interval=100, capabilities=caps, label=BENIGN)


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory):
    """Synthetic sessions from two origins (two networks), as the trainer expects."""
    tmp = tmp_path_factory.mktemp("ml")
    sources = []
    for name, aps in (("home", (ap("02:00:00:00:01:01", "HomeNet", 2457, 0x1431),
                                ap("02:00:aa:00:02:01", "HomeNet", 2457, 0x0431, ("WPA", "WPA2")))),
                      ("office", (ap("02:00:bb:00:01:01", "OfficeNet", 2412, 0x1511),
                                  ap("02:00:bb:00:01:02", "OfficeNet", 5180, 0x1511)))):
        path = tmp / f"{name}.jsonl"
        for i in range(3):
            recording.append(path, Snapshot(float(i), "test", aps, {"ssid": aps[0].ssid}))
        sources.append(path)
    out = tmp / "synthetic.jsonl"
    synth.generate(sources, out, learn_scans=4, attack_scans=3, repeats=4, seed=2)
    return out


@pytest.fixture(scope="module")
def model_path(synthetic, tmp_path_factory):
    path = tmp_path_factory.mktemp("model") / "rf.joblib"
    train.main([str(synthetic), "-o", str(path)])
    return path


def test_load_groups_rows_by_origin(synthetic):
    data = train.load([synthetic])
    assert set(data.groups) == {"home|HomeNet", "office|OfficeNet"}
    assert len(data.signals) == len(data.y) == len(data.scenarios)
    assert len(data.matrix()[0]) == len(SIGNALS)
    assert data.synthetic == len(data.y)
    assert {s for s, y in zip(data.scenarios, data.y) if y} == set(synth.ATTACK_SCENARIOS)


def test_cross_validation_needs_two_origins(synthetic):
    data = train.load([synthetic])
    oof = train.cross_validate(data, seed=0)
    assert len(oof) == len(data.y) and all(0.0 <= p <= 1.0 for p in oof)
    one = train.Dataset(y=data.y, groups=["x"] * len(data.y), signals=data.signals)
    assert train.cross_validate(one, seed=0) is None


def test_saved_model_carries_signals_and_info(model_path):
    bundle = joblib.load(model_path)
    assert bundle["signals"] == list(SIGNALS)
    assert bundle["info"]["origins"] == ["home|HomeNet", "office|OfficeNet"]
    assert set(bundle["info"]["cv"]) == {"ml", "naive", "weighted"}


def test_ml_scorer_flags_twin_and_explains(model_path, synthetic):
    scorer = make_scorer("ml", model_path)
    sessions = recording.sessions(recording.read(synthetic), "x")
    snaps = next(s for (sid, _), s in sessions.items() if "open_network" in sid)
    base = baseline_mod.build(snaps[:4], snaps[0].meta["ssid"])
    verdicts = assess(scorer, snaps[-1], base)
    twin = next(v for v in verdicts if v.ap.label == EVIL_TWIN)
    assert twin.level == LIKELY
    assert "security_downgrade" in twin.reasons
    assert all(r not in ("signal_delta_db", "cluster_distance") for r in twin.reasons)
    importance = [scorer.importance[r] for r in twin.reasons]
    assert importance == sorted(importance, reverse=True)
    assert {v.level for v in verdicts if v.ap.label == BENIGN} == {SAFE}


def test_model_with_other_signals_is_rejected(model_path, tmp_path):
    bundle = joblib.load(model_path)
    bundle["signals"] = bundle["signals"][:-1]  # names no longer match the model's inputs
    stale = tmp_path / "stale.joblib"
    joblib.dump(bundle, stale)
    with pytest.raises(ModelError, match="retrain"):
        MLScorer.load(stale)
    with pytest.raises(ModelError, match="no model"):
        MLScorer.load(tmp_path / "missing.joblib")


def test_training_refuses_single_class(tmp_path):
    path = tmp_path / "benign.jsonl"
    aps = (ap("02:00:00:00:01:01", "HomeNet", 2457, 0x1431),)
    for i in range(8):
        recording.append(path, Snapshot(float(i), "test", aps, {"ssid": "HomeNet"}))
    with pytest.raises(SystemExit, match="both benign and evil_twin"):
        train.main([str(path), "-o", str(tmp_path / "m.joblib")])
