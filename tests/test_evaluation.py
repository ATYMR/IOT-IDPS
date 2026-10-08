import numpy as np

from idps.evaluation import chronological_split, extract, report_markdown, train_and_evaluate
from idps.synthetic import ATTACK_TYPES, NORMAL, generate, load_jsonl, save_jsonl


def test_generator_is_deterministic():
    a = generate(n_windows=300, seed=3)
    b = generate(n_windows=300, seed=3)
    assert [r.payload for r in a] == [r.payload for r in b]


def test_attacks_only_after_start_fraction(synthetic_records):
    data = extract(synthetic_records)
    labels, devices = data["labels"], data["devices"]
    for dev in set(devices):
        lab = labels[devices == dev]
        first_attack = np.flatnonzero(lab != NORMAL)[0]
        assert first_attack >= int(len(lab) * 0.75)
    assert set(labels) <= {NORMAL, *ATTACK_TYPES}


def test_synthetic_payloads_pass_production_validation(synthetic_records):
    assert extract(synthetic_records)["skipped"] == 0


def test_chronological_split_has_no_overlap_or_reordering():
    devices = np.array(["a", "b"] * 50)
    tr, va, te = chronological_split(devices, 0.6, 0.8)
    assert not set(tr) & set(va) and not set(va) & set(te)
    for dev in "ab":
        idx = lambda s: [i for i in s if devices[i] == dev]  # noqa: E731
        assert max(idx(tr)) < min(idx(va)) and max(idx(va)) < min(idx(te))


def test_train_and_evaluate_report(trained):
    detector, report = trained
    assert report["data"]["test_attack_windows"] > 0
    assert report["data"]["attack_windows_dropped_from_train_val"] == 0
    for name in ("ensemble", "hybrid", "iforest", "zscore"):
        m = report["detectors"][name]
        assert 0 <= m["precision"] <= 1 and 0 <= m["recall"] <= 1
    # Sanity floor on synthetic data: these are regression guards, not claims.
    ens = report["detectors"]["ensemble"]
    assert ens["fpr"] < 0.05
    assert ens["recall"] > 0.3
    assert "Attack type" in report_markdown(report)


def test_normal_only_dataset_reports_fpr(synthetic_records):
    normal = [r for r in synthetic_records if r.label == NORMAL]
    _, report = train_and_evaluate(normal, n_estimators=50)
    assert "note" in report and "fpr" in report["detectors"]["ensemble"]


def test_jsonl_roundtrip(tmp_path):
    recs = generate(n_windows=50, seed=1)
    save_jsonl(recs, tmp_path / "d.jsonl")
    assert load_jsonl(tmp_path / "d.jsonl") == recs


def test_benchmark_aggregates_runs():
    from idps.evaluation import benchmark, benchmark_markdown

    result = benchmark([1, 2], n_windows=900, n_estimators=30)
    assert set(result["summary"]) == {"ensemble", "iforest", "zscore", "hybrid"}
    assert 0 <= result["summary"]["ensemble"]["recall"]["mean"] <= 1
    assert "±" in benchmark_markdown(result)
