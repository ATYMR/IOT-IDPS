# Models

Trained models are **not** committed. They are generated in under a minute:

```bash
python -m idps generate-data
python -m idps train                 # -> models/isolation_forest.joblib + reports/train_eval.{json,md}
```

The model file stores: format version, detector kind, feature names,
scikit-learn version, both calibrated thresholds, z-score statistics,
training sizes, timestamp, and the evaluation config. Loading fails with a
clear error if the format or feature set does not match. A warning is logged
on a scikit-learn version mismatch.

**Security:** joblib files are pickles. Loading one can execute arbitrary
code. Only load models you trained yourself.

If no model is present, `idps listen` runs in rules-only (degraded) mode.
