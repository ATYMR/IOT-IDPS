import numpy as np
import pytest

from idps.detector import AnomalyDetector, ModelError
from idps.features import FEATURE_NAMES


def normal(n, seed):
    rng = np.random.default_rng(seed)
    return np.column_stack([
        rng.poisson(0.05, n) / 5, np.zeros(n), np.abs(rng.normal(0, 0.6, n)),
        np.zeros(n), np.zeros(n), np.full(n, 5.0),
    ])


@pytest.fixture(scope="module")
def det():
    return AnomalyDetector(n_estimators=100, target_fpr=0.02).fit(normal(3000, 1), normal(1500, 2))


def test_fpr_close_to_target_on_unseen_normal(det):
    fpr = det.predict(normal(4000, 3)).mean()
    assert fpr < 0.05


def test_obvious_attacks_flagged(det):
    attacks = np.array([
        [30.0, 5.0, 0.5, 0, 0, 5],     # command flood
        [0.0, 0.0, 60.0, 0, 0, 5],     # heap exhaustion
        [0.0, 0.0, 0.5, 3, 4, 15],     # deauth / reconnect storm
    ])
    assert det.predict(attacks).tolist() == [1, 1, 1]
    conf = det.confidence(det.score(attacks))
    assert np.all(conf > 0.5)


def test_confidence_is_monotonic(det):
    s = np.array([0.5, 1.0, 1.5, 3.0])
    c = det.confidence(s)
    assert np.all(np.diff(c) > 0) and abs(c[1] - 0.5) < 1e-9


def test_explain_mentions_feature(det):
    text = det.explain([0.0, 0.0, 60.0, 0, 0, 5])
    assert "heap_drop_kb" in text


def test_save_load_roundtrip(det, tmp_path):
    path = tmp_path / "m.joblib"
    det.save(path)
    loaded = AnomalyDetector.load(path)
    x = normal(50, 9)
    np.testing.assert_allclose(loaded.score(x), det.score(x))


def test_load_missing_or_corrupt(tmp_path):
    with pytest.raises(ModelError):
        AnomalyDetector.load(tmp_path / "nope.joblib")
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a pickle")
    with pytest.raises(ModelError):
        AnomalyDetector.load(bad)


def test_feature_mismatch_rejected(det, tmp_path):
    import joblib

    path = tmp_path / "m.joblib"
    det.save(path)
    blob = joblib.load(path)
    blob["feature_names"] = ["a", "b"]
    joblib.dump(blob, path)
    with pytest.raises(ModelError):
        AnomalyDetector.load(path)


def test_input_validation(det):
    with pytest.raises(ModelError):
        det.score([[1.0, 2.0]])
    with pytest.raises(ModelError):
        det.score([[np.nan] * len(FEATURE_NAMES)])
    with pytest.raises(ModelError):
        AnomalyDetector().score(normal(5, 1))
    with pytest.raises(ModelError):
        AnomalyDetector().fit(normal(10, 1), normal(10, 2))


@pytest.mark.parametrize("kind", ["iforest", "zscore"])
def test_single_component_kinds(kind, tmp_path):
    d = AnomalyDetector(kind=kind, n_estimators=50, target_fpr=0.02).fit(normal(2000, 1), normal(1000, 2))
    assert d.predict([[0.0, 0.0, 60.0, 0, 0, 5]]).tolist() == [1]  # large heap drop
    d.save(tmp_path / "m.joblib")
    assert AnomalyDetector.load(tmp_path / "m.joblib").kind == kind


def test_unknown_kind_rejected():
    with pytest.raises(ModelError):
        AnomalyDetector(kind="magic").fit(normal(100, 1), normal(100, 2))


def test_ensemble_covers_iforest_extrapolation_gap():
    # auth_fail_rate is constant (0) in this training data, so Isolation Forest never splits on it
    # and whether it flags an out-of-range flood depends on the random seed. The z-score component
    # makes the ensemble catch it for every seed. This is the rationale documented in detector.py.
    flood = [[30.0, 5.0, 0.5, 0, 0, 5]]
    train, val = normal(2000, 1), normal(1000, 2)
    iforest_hits = []
    for seed in range(5):
        kw = dict(n_estimators=50, target_fpr=0.02, random_state=seed)
        assert AnomalyDetector(kind="ensemble", **kw).fit(train, val).predict(flood)[0] == 1
        iforest_hits.append(AnomalyDetector(kind="iforest", **kw).fit(train, val).predict(flood)[0])
    assert 0 in iforest_hits
