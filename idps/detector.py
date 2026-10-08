"""Anomaly detector: Isolation Forest + per-feature z-score, jointly calibrated.

Design notes
------------
* Trained on normal telemetry only (semi-supervised novelty detection).
* Two components, each calibrated on *held-out* normal windows to flag
  ``target_fpr / 2`` of them, so the union stays near ``target_fpr``:

  - Isolation Forest captures multivariate structure. It cannot extrapolate:
    a value far beyond the training range scores like the most extreme
    training point, and sparse count features (reconnects) that are constant
    in most bootstrap subsamples are rarely split on. On the synthetic data
    this made IF alone miss most reconnect-based attacks.
  - A per-feature z-score (max |z| over features) catches those univariate
    extremes, but misses combinations of individually modest deviations.

  Ablation numbers are produced by ``idps train`` (see docs/evaluation.md).
* Each component score is divided by its own threshold and the maximum is
  taken, so the combined score is anomalous iff it is > 1.0.
* Isolation Forest is invariant to per-feature monotonic scaling, so no
  scaler is fitted; the z-score component standardises internally.
* ``confidence`` is a logistic squashing of the distance above the threshold
  in units of the normal-score spread. It is a monotonic severity signal,
  NOT a calibrated probability of attack.
* ``contamination`` is left at "auto": setting it to 0.1 on clean training
  data (as the original prototype did) forces ~10 % false positives.
* ``kind`` selects the components ("ensemble", "iforest" or "zscore"); the
  FPR budget is split evenly between the enabled components. On the
  synthetic benchmark the z-score baseline performs as well as the ensemble
  (see docs/evaluation.md), so the choice should be revisited on real data.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES

log = logging.getLogger(__name__)

MODEL_FORMAT_VERSION = 2
THRESHOLD = 1.0  # combined score threshold (scores are normalised by component thresholds)
KINDS: dict[str, tuple[str, ...]] = {
    "ensemble": ("iforest", "zscore"),
    "iforest": ("iforest",),
    "zscore": ("zscore",),
}


class ModelError(RuntimeError):
    pass


@dataclass
class AnomalyDetector:
    kind: str = "ensemble"
    n_estimators: int = 200
    random_state: int = 42
    target_fpr: float = 0.01
    forest: IsolationForest | None = None
    if_threshold: float = float("nan")
    z_mean: np.ndarray | None = None
    z_std: np.ndarray | None = None
    z_threshold: float = float("nan")
    scale: float = 1.0
    metadata: dict = field(default_factory=dict)

    threshold = THRESHOLD

    def fit(self, x_train: np.ndarray, x_val_normal: np.ndarray) -> AnomalyDetector:
        x_train = _as_matrix(x_train)
        x_val_normal = _as_matrix(x_val_normal)
        if len(x_train) < 50 or len(x_val_normal) < 50:
            raise ModelError("need at least 50 training and 50 validation windows")
        if not 0 < self.target_fpr < 0.5:
            raise ModelError("target_fpr must be in (0, 0.5)")
        if self.kind not in KINDS:
            raise ModelError(f"unknown detector kind {self.kind!r}; choose from {sorted(KINDS)}")

        q = 1.0 - self.target_fpr / len(KINDS[self.kind])
        # The forest is always fitted (cheap) so `component_scores` and
        # `explain` work for every kind; only enabled components vote.
        self.forest = IsolationForest(
            n_estimators=self.n_estimators, contamination="auto", random_state=self.random_state,
        ).fit(x_train)
        self.if_threshold = float(np.quantile(self._if_raw(x_val_normal), q))

        self.z_mean = x_train.mean(axis=0)
        std = x_train.std(axis=0)
        self.z_std = np.where(std > 1e-9, std, 1.0)
        self.z_threshold = float(np.quantile(self._z_raw(x_val_normal), q))

        self.scale = max(float(np.std(self.score(x_val_normal))), 1e-6)
        self.metadata.update(
            n_train=int(len(x_train)),
            n_val=int(len(x_val_normal)),
            trained_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        return self

    # ------------------------------------------------------------ scoring

    def _check_fitted(self) -> None:
        if self.forest is None or self.z_mean is None:
            raise ModelError("model is not fitted")

    def _if_raw(self, x: np.ndarray) -> np.ndarray:
        return -self.forest.score_samples(x)

    def _z_matrix(self, x: np.ndarray) -> np.ndarray:
        return np.abs((x - self.z_mean) / self.z_std)

    def _z_raw(self, x: np.ndarray) -> np.ndarray:
        return self._z_matrix(x).max(axis=1)

    def component_scores(self, x) -> tuple[np.ndarray, np.ndarray]:
        """(isolation-forest, z-score) components, each normalised to threshold 1.0."""
        self._check_fitted()
        x = _as_matrix(x)
        return self._if_raw(x) / self.if_threshold, self._z_raw(x) / self.z_threshold

    def score(self, x) -> np.ndarray:
        """Combined anomaly score: higher is more anomalous, > 1.0 is flagged."""
        s_if, s_z = self.component_scores(x)
        enabled = KINDS[self.kind]
        if enabled == ("iforest",):
            return s_if
        if enabled == ("zscore",):
            return s_z
        return np.maximum(s_if, s_z)

    def confidence(self, scores) -> np.ndarray:
        z = (np.asarray(scores, dtype=float) - THRESHOLD) / self.scale
        return 1.0 / (1.0 + np.exp(-np.clip(z, -50, 50)))

    def predict(self, x) -> np.ndarray:
        """1 = anomalous, 0 = normal."""
        return (self.score(x) > THRESHOLD).astype(int)

    def explain(self, row) -> str:
        """Short human-readable reason for one window."""
        s_if, s_z = self.component_scores(row)
        zs = self._z_matrix(_as_matrix(row))[0]
        top = int(np.argmax(zs))
        return (f"[{self.kind}] iforest={s_if[0]:.2f} zscore={s_z[0]:.2f} "
                f"(most deviant feature: {FEATURE_NAMES[top]}, |z|={zs[top]:.1f})")

    # ------------------------------------------------------------ persistence

    def save(self, path: str | Path) -> None:
        import joblib

        self._check_fitted()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "format_version": MODEL_FORMAT_VERSION,
                "kind": self.kind,
                "feature_names": list(FEATURE_NAMES),
                "sklearn_version": sklearn.__version__,
                "forest": self.forest,
                "if_threshold": self.if_threshold,
                "z_mean": self.z_mean.tolist(),
                "z_std": self.z_std.tolist(),
                "z_threshold": self.z_threshold,
                "scale": self.scale,
                "target_fpr": self.target_fpr,
                "n_estimators": self.n_estimators,
                "random_state": self.random_state,
                "metadata": self.metadata,
            },
            path,
        )

    @classmethod
    def load(cls, path: str | Path) -> AnomalyDetector:
        """Load a model file. joblib uses pickle: only load files you trust."""
        import joblib

        path = Path(path)
        if not path.is_file():
            raise ModelError(f"model file not found: {path}")
        try:
            blob = joblib.load(path)
        except Exception as exc:  # corrupt or incompatible pickle
            raise ModelError(f"cannot load model {path}: {exc}") from exc
        if not isinstance(blob, dict) or blob.get("format_version") != MODEL_FORMAT_VERSION:
            raise ModelError("unsupported model format version; retrain with `idps train`")
        if blob.get("feature_names") != list(FEATURE_NAMES):
            raise ModelError("model was trained on a different feature set; retrain it")
        if blob.get("sklearn_version") != sklearn.__version__:
            log.warning("model trained with scikit-learn %s, running %s",
                        blob.get("sklearn_version"), sklearn.__version__)
        if blob.get("kind") not in KINDS:
            raise ModelError(f"unknown detector kind in model file: {blob.get('kind')!r}")
        return cls(
            kind=blob["kind"],
            n_estimators=blob["n_estimators"],
            random_state=blob["random_state"],
            target_fpr=blob["target_fpr"],
            forest=blob["forest"],
            if_threshold=blob["if_threshold"],
            z_mean=np.asarray(blob["z_mean"], dtype=float),
            z_std=np.asarray(blob["z_std"], dtype=float),
            z_threshold=blob["z_threshold"],
            scale=blob["scale"],
            metadata=blob.get("metadata", {}),
        )


def _as_matrix(x) -> np.ndarray:
    arr = np.asarray(x, dtype=float)
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    if arr.ndim != 2 or arr.shape[1] != len(FEATURE_NAMES):
        raise ModelError(f"expected shape (n, {len(FEATURE_NAMES)}), got {arr.shape}")
    if not np.all(np.isfinite(arr)):
        raise ModelError("features contain NaN or infinity")
    return arr
