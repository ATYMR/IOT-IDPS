"""Training/evaluation pipeline.

Methodology
-----------
1. Every record goes through the production path: ``decode_telemetry`` ->
   ``DeviceTracker`` -> ``FEATURE_NAMES`` vector.
2. Each device's stream is split *chronologically*: the first ``train_frac``
   of windows for training, the next slice up to ``val_frac`` for threshold
   calibration, the rest for testing. No shuffling, so no temporal leakage.
3. Train and validation sets use normal windows only (novelty detection);
   any labelled attack windows inside them are dropped and counted.
4. Every detector gets the same total false-positive budget (``target_fpr``)
   calibrated on the validation windows.
5. Reported on the untouched test slice:

   - each detector kind (``ensemble``, ``iforest``, ``zscore``; see detector.py)
   - ``hybrid``: the selected kind OR the command-rejection rule, which is
     what the engine actually alerts on

6. ``benchmark`` repeats this over several generator seeds and reports
   mean +/- std, because single-seed results on synthetic data are noisy.
"""

from __future__ import annotations

import time
from collections import defaultdict

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from .detector import KINDS, AnomalyDetector
from .features import FEATURE_NAMES, DeviceTracker, feature_vector
from .protocol import DEFAULT_TOPIC_PREFIX, ProtocolError, decode_telemetry, parse_topic
from .synthetic import NORMAL, Record

DETECTOR_LABELS = {
    "ensemble": "Ensemble (IF + z-score)",
    "iforest": "Isolation Forest only",
    "zscore": "z-score only (baseline)",
    "hybrid": "Hybrid: selected detector OR rejection rule (engine behaviour)",
}


def extract(records: list[Record], interval_s: float = 5.0, prefix: str = DEFAULT_TOPIC_PREFIX) -> dict:
    """Run records through the production feature path."""
    tracker = DeviceTracker(nominal_interval_s=interval_s)
    rows, labels, devices, auth_fail, skipped = [], [], [], [], 0
    for r in records:
        try:
            device_id, kind = parse_topic(r.topic, prefix)
            if kind != "telemetry":
                continue
            t = decode_telemetry(r.payload, device_id)
        except ProtocolError:
            skipped += 1
            continue
        obs = tracker.observe(t, r.t)
        if obs.features is None:
            skipped += 1
            continue
        rows.append(feature_vector(obs.features))
        labels.append(r.label)
        devices.append(device_id)
        auth_fail.append(t.auth_fail)
    return {
        "X": np.asarray(rows, dtype=float).reshape(-1, len(FEATURE_NAMES)),
        "labels": np.asarray(labels),
        "devices": np.asarray(devices),
        "auth_fail": np.asarray(auth_fail),
        "skipped": skipped,
    }


def chronological_split(devices: np.ndarray, train_frac: float, val_frac: float):
    """Index arrays (train, val, test), split per device in arrival order."""
    if not 0 < train_frac < val_frac < 1:
        raise ValueError("require 0 < train_frac < val_frac < 1")
    train, val, test = [], [], []
    by_device = defaultdict(list)
    for i, d in enumerate(devices):
        by_device[d].append(i)
    for idx in by_device.values():
        n = len(idx)
        a, b = int(n * train_frac), int(n * val_frac)
        train += idx[:a]
        val += idx[a:b]
        test += idx[b:]
    return np.array(train, dtype=int), np.array(val, dtype=int), np.array(test, dtype=int)


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None = None) -> dict:
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "precision": float(p), "recall": float(r), "f1": float(f1),
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if scores is not None and 0 < y_true.sum() < len(y_true):
        out["roc_auc"] = float(roc_auc_score(y_true, scores))
        out["pr_auc"] = float(average_precision_score(y_true, scores))
    return out


def _episodes(labels: np.ndarray, devices: np.ndarray) -> list[tuple[str, np.ndarray]]:
    """Contiguous runs of the same attack label per device -> (label, positions)."""
    episodes = []
    by_device = defaultdict(list)
    for pos, d in enumerate(devices):
        by_device[d].append(pos)
    for positions in by_device.values():
        run: list[int] = []
        for pos in positions + [None]:
            label = labels[pos] if pos is not None else None
            if run and label != labels[run[0]]:
                if labels[run[0]] != NORMAL:
                    episodes.append((str(labels[run[0]]), np.array(run)))
                run = []
            if pos is not None:
                run.append(pos)
    return episodes


def episode_metrics(labels: np.ndarray, devices: np.ndarray, y_pred: np.ndarray) -> dict:
    per_type: dict[str, list] = defaultdict(list)
    for label, positions in _episodes(labels, devices):
        hits = np.flatnonzero(y_pred[positions])
        per_type[label].append(int(hits[0]) if len(hits) else None)
    result = {}
    for label, delays in sorted(per_type.items()):
        detected = [d for d in delays if d is not None]
        result[label] = {
            "episodes": len(delays),
            "detected": len(detected),
            "mean_windows_to_detect": float(np.mean(detected)) if detected else None,
        }
    return result


def per_type_recall(labels: np.ndarray, y_pred: np.ndarray) -> dict:
    out = {}
    for label in sorted(set(labels.tolist()) - {NORMAL}):
        mask = labels == label
        out[label] = {"windows": int(mask.sum()), "recall": float(y_pred[mask].mean())}
    return out


def _latency_us(detector: AnomalyDetector, x: np.ndarray, n_single: int = 200) -> dict:
    sample = x[: min(len(x), n_single)]
    start = time.perf_counter()
    for row in sample:
        detector.score(row.reshape(1, -1))
    single = (time.perf_counter() - start) / len(sample) * 1e6
    start = time.perf_counter()
    detector.score(x)
    batch = (time.perf_counter() - start) / len(x) * 1e6
    return {"single_window_us": round(single, 1), "batched_per_window_us": round(batch, 2)}


def train_and_evaluate(records: list[Record], *, train_frac: float = 0.6, val_frac: float = 0.75,
                       target_fpr: float = 0.01, n_estimators: int = 200, seed: int = 42,
                       kind: str = "ensemble", rejection_threshold: int = 3, interval_s: float = 5.0,
                       prefix: str = DEFAULT_TOPIC_PREFIX,
                       compare: bool = True) -> tuple[AnomalyDetector, dict]:
    """Fit the selected detector kind; with ``compare`` also fit the other kinds on the same split."""
    data = extract(records, interval_s=interval_s, prefix=prefix)
    x, labels, devices, auth_fail = data["X"], data["labels"], data["devices"], data["auth_fail"]
    train, val, test = chronological_split(devices, train_frac, val_frac)

    is_normal = labels == NORMAL
    dropped = int((~is_normal[train]).sum() + (~is_normal[val]).sum())
    train, val = train[is_normal[train]], val[is_normal[val]]

    def fit(k: str) -> AnomalyDetector:
        return AnomalyDetector(kind=k, n_estimators=n_estimators, random_state=seed,
                               target_fpr=target_fpr).fit(x[train], x[val])

    detector = fit(kind)

    y_true = (~is_normal[test]).astype(int)
    scores = detector.score(x[test])
    report: dict = {
        "data": {
            "windows_total": int(len(x)), "skipped_records": data["skipped"],
            "train_windows": int(len(train)), "val_windows": int(len(val)),
            "test_windows": int(len(test)), "test_attack_windows": int(y_true.sum()),
            "attack_windows_dropped_from_train_val": dropped,
            "devices": sorted(set(devices.tolist())),
        },
        "config": {"kind": kind, "train_frac": train_frac, "val_frac": val_frac, "target_fpr": target_fpr,
                   "n_estimators": n_estimators, "seed": seed,
                   "rejection_rule_threshold": rejection_threshold, "features": list(FEATURE_NAMES)},
        "latency": _latency_us(detector, x[test]),
    }
    detector.metadata["evaluation"] = {"data": report["data"], "config": report["config"]}

    if y_true.sum() == 0:
        # e.g. a real baseline capture with no labelled attacks: only the
        # false-positive rate on unseen normal traffic can be measured.
        report["note"] = "test split has no labelled attacks; only the false-positive rate is reported"
        report["detectors"] = {kind: {"fpr": float((scores > detector.threshold).mean())}}
        return detector, report

    preds = {kind: ((scores > detector.threshold).astype(int), scores)}
    for other in KINDS if compare else ():
        if other != kind:
            s_other = fit(other).score(x[test])
            preds[other] = ((s_other > 1.0).astype(int), s_other)
    preds["hybrid"] = (preds[kind][0] | (auth_fail[test] >= rejection_threshold).astype(int), None)

    test_labels, test_devices = labels[test], devices[test]
    report["detectors"] = {name: binary_metrics(y_true, y, s) for name, (y, s) in preds.items()}
    report["per_attack_recall"] = {name: per_type_recall(test_labels, y) for name, (y, _) in preds.items()}
    report["episodes"] = {name: episode_metrics(test_labels, test_devices, preds[name][0])
                          for name in ("hybrid", kind)}
    return detector, report


def evaluate_model(detector: AnomalyDetector, records: list[Record], interval_s: float = 5.0,
                   prefix: str = DEFAULT_TOPIC_PREFIX, rejection_threshold: int = 3) -> dict:
    """Evaluate an already-trained model on a separate labelled dataset."""
    data = extract(records, interval_s=interval_s, prefix=prefix)
    y_true = (data["labels"] != NORMAL).astype(int)
    scores = detector.score(data["X"])
    y_ens = (scores > detector.threshold).astype(int)
    y_hybrid = y_ens | (data["auth_fail"] >= rejection_threshold).astype(int)
    return {
        "windows": int(len(y_true)), "attack_windows": int(y_true.sum()),
        "detectors": {detector.kind: binary_metrics(y_true, y_ens, scores),
                      "hybrid": binary_metrics(y_true, y_hybrid)},
        "per_attack_recall": {detector.kind: per_type_recall(data["labels"], y_ens),
                              "hybrid": per_type_recall(data["labels"], y_hybrid)},
    }


def report_markdown(report: dict) -> str:
    det = report["detectors"]
    lines = ["| Detector | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |",
             "|---|---|---|---|---|---|---|"]
    for key, m in det.items():
        auc = f"{m['roc_auc']:.3f}" if "roc_auc" in m else "n/a"
        ap = f"{m['pr_auc']:.3f}" if "pr_auc" in m else "n/a"
        lines.append(f"| {DETECTOR_LABELS.get(key, key)} | {m['precision']:.3f} | {m['recall']:.3f} "
                     f"| {m['f1']:.3f} | {m['fpr']:.4f} | {auc} | {ap} |")

    pr = report["per_attack_recall"]
    names = list(pr)
    lines += ["", "Per-attack window recall:", "",
              "| Attack type | Windows | " + " | ".join(names) + " |",
              "|---|---|" + "---|" * len(names)]
    first = pr[names[0]]
    for label, v in first.items():
        cells = " | ".join(f"{pr[n][label]['recall']:.3f}" for n in names)
        lines.append(f"| {label} | {v['windows']} | {cells} |")

    if "episodes" in report:
        kind = report["config"]["kind"]
        lines += ["", "Episode-level detection (an episode counts as detected if any of its windows is flagged):",
                  "", "| Attack type | Episodes | Detected (hybrid) | Mean windows to first alert (hybrid) "
                  f"| Detected ({kind} alone) |", "|---|---|---|---|---|"]
        hyb, alone = report["episodes"]["hybrid"], report["episodes"][kind]
        for label, v in hyb.items():
            delay = "n/a" if v["mean_windows_to_detect"] is None else f"{v['mean_windows_to_detect']:.2f}"
            lines.append(f"| {label} | {v['episodes']} | {v['detected']} | {delay} | {alone[label]['detected']} |")
    return "\n".join(lines)


def benchmark(seeds: list[int], n_windows: int = 4000, target_fpr: float = 0.01,
              n_estimators: int = 200) -> dict:
    """Repeat train/evaluate over generator seeds; return mean/std per detector and metric."""
    from .synthetic import generate

    per_run: dict[str, list[dict]] = defaultdict(list)
    for seed in seeds:
        _, rep = train_and_evaluate(generate(n_windows=n_windows, seed=seed), seed=seed,
                                    target_fpr=target_fpr, n_estimators=n_estimators)
        for name, m in rep["detectors"].items():
            per_run[name].append(m)
    summary: dict[str, dict] = {}
    for name, runs in per_run.items():
        summary[name] = {}
        for metric in ("precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"):
            vals = [r[metric] for r in runs if metric in r]
            if vals:
                summary[name][metric] = {"mean": float(np.mean(vals)), "std": float(np.std(vals))}
    return {"seeds": list(seeds), "n_windows": n_windows, "target_fpr": target_fpr, "summary": summary}


def benchmark_markdown(result: dict) -> str:
    metrics = ("precision", "recall", "f1", "fpr", "roc_auc", "pr_auc")
    header = ("Precision", "Recall", "F1", "FPR", "ROC-AUC", "PR-AUC")
    seeds = result["seeds"]
    lines = [f"Seeds {seeds[0]}..{seeds[-1]} ({len(seeds)} runs), {result['n_windows']} windows/device, "
             f"target FPR {result['target_fpr']}. Values are mean ± std across runs.", "",
             "| Detector | " + " | ".join(header) + " |",
             "|---|" + "---|" * len(metrics)]
    for name, stats in result["summary"].items():
        cells = [f"{stats[m]['mean']:.3f} ± {stats[m]['std']:.3f}" if m in stats else "n/a" for m in metrics]
        lines.append(f"| {DETECTOR_LABELS.get(name, name)} | " + " | ".join(cells) + " |")
    return "\n".join(lines)
