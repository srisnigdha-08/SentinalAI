"""
Input-drift monitor for the inference engine.

Reference: the training statistics stored in the deployed pipeline's StandardScaler (per-feature mean_
and var_ of the data the model was fitted on). Live: a rolling window of the raw feature vectors the
engine actually scored (evaluation calls and rule-synthesised honeypot vectors are not recorded).

Per feature it reports the standardised mean shift |mean_live - mean_train| / sd_train and the variance
ratio var_live / var_train. A feature drifts when the shift exceeds SHIFT_LIMIT (0.5 = a "medium"
effect size) or the variance ratio leaves [1/VAR_RATIO_LIMIT, VAR_RATIO_LIMIT]. The window as a whole
is reported as "drift" when at least DRIFT_FRACTION of the informative features drift. These are
screening statistics, not a hypothesis test: they flag that inputs no longer look like the training
data, which is the trigger for re-evaluation/retraining (training/retrain_from_samples.py).
"""
import os
import threading
from collections import Counter, deque

import numpy as np

# Population Stability Index against per-feature quantile bins of the BENIGN training rows (M7). The scaler
# mean/var reference (report) mixes in capped attack classes, and mean/variance are fragile on heavy-tailed
# flow features; PSI on benign-predicted live flows compares like with like. PSI > 0.25 = major shift.
PSI_LIMIT = 0.25
PSI_BINS = 10
_PSI_EPS = 1e-4


def _bin_index(values, edges):
    return np.searchsorted(np.asarray(edges, dtype=float), np.asarray(values, dtype=float), side="right")


def benign_reference(X_benign, bins=PSI_BINS) -> dict:
    """Per-feature interior quantile edges and the fraction of benign training rows in each bin."""
    X = np.asarray(X_benign, dtype=float)
    qs = np.linspace(0, 1, bins + 1)[1:-1]
    edges, fractions = [], []
    for j in range(X.shape[1]):
        e = np.unique(np.quantile(X[:, j], qs))
        counts = np.bincount(_bin_index(X[:, j], e), minlength=len(e) + 1)
        edges.append([float(v) for v in e])
        fractions.append([round(float(c) / len(X), 6) for c in counts])
    return {"source": "benign training rows", "rows": int(len(X)), "bins": bins, "edges": edges, "fractions": fractions}


def psi(expected, actual) -> float:
    e = np.clip(np.asarray(expected, dtype=float), _PSI_EPS, None)
    a = np.clip(np.asarray(actual, dtype=float), _PSI_EPS, None)
    return float(np.sum((a - e) * np.log(a / e)))


SHIFT_LIMIT = 0.5
VAR_RATIO_LIMIT = 4.0
DRIFT_FRACTION = 0.10


def _int_env(name, default):
    try:
        value = int(os.getenv(name, ""))
        return value if value > 0 else default
    except ValueError:
        return default


class DriftMonitor:
    def __init__(self, window=None, min_samples=None):
        self.window = window or _int_env("DRIFT_WINDOW", 2000)
        self.min_samples = min_samples or _int_env("DRIFT_MIN_SAMPLES", 200)
        self._vectors = deque(maxlen=self.window)
        self._classes = deque(maxlen=self.window)
        self._lock = threading.Lock()

    def record(self, feature_vector, predicted_class=None):
        if feature_vector is None:
            return
        vec = np.asarray(feature_vector, dtype=float)
        if vec.ndim != 1 or not np.isfinite(vec).all():
            return
        with self._lock:
            self._vectors.append(vec)
            self._classes.append(predicted_class)

    def recent(self, n):
        """The last n recorded feature vectors and their predicted classes."""
        with self._lock:
            vectors, classes = list(self._vectors)[-n:], list(self._classes)[-n:]
        return vectors, classes

    def report(self, reference_mean, reference_var, feature_names):
        with self._lock:
            n = len(self._vectors)
            live = np.vstack(self._vectors) if n else None
            classes = Counter(c for c in self._classes if c is not None)
        base = {"window": self.window, "samples": n, "min_samples": self.min_samples,
                "limits": {"shift": SHIFT_LIMIT, "variance_ratio": VAR_RATIO_LIMIT, "drift_fraction": DRIFT_FRACTION},
                "recent_class_mix": dict(classes.most_common())}
        if n < self.min_samples:
            return {**base, "status": "insufficient_data", "drifted_features": [], "drifted_fraction": None}

        mean_ref = np.asarray(reference_mean, dtype=float)
        var_ref = np.asarray(reference_var, dtype=float)
        informative = var_ref > 0  # zero-variance training features (e.g. time-of-day) carry no reference
        sd_ref = np.sqrt(np.where(informative, var_ref, 1.0))
        shift = np.abs(live.mean(axis=0) - mean_ref) / sd_ref
        var_ratio = (live.var(axis=0) + 1e-12) / np.where(informative, var_ref, 1.0)
        drifted = informative & ((shift > SHIFT_LIMIT) | (var_ratio > VAR_RATIO_LIMIT) | (var_ratio < 1 / VAR_RATIO_LIMIT))

        rows = [{"feature": feature_names[i], "mean_shift_sd": round(float(shift[i]), 3),
                 "variance_ratio": round(float(var_ratio[i]), 3)}
                for i in np.argsort(-np.where(informative, shift, -1))[:10] if informative[i]]
        fraction = float(drifted.sum() / max(1, informative.sum()))
        return {**base,
                "status": "drift" if fraction >= DRIFT_FRACTION else "ok",
                "informative_features": int(informative.sum()),
                "drifted_fraction": round(fraction, 4),
                "drifted_features": [feature_names[i] for i in np.flatnonzero(drifted)],
                "top_shifts": rows}

    def report_psi(self, reference: dict, feature_names):
        """PSI of the benign-predicted flows in the window against the benign training reference."""
        with self._lock:
            pairs = [(v, c) for v, c in zip(self._vectors, self._classes)]
        classes = Counter(c for _, c in pairs if c is not None)
        benign = [v for v, c in pairs if c == "BENIGN"]
        base = {"method": "psi_benign_quantiles", "window": self.window, "samples": len(pairs),
                "benign_samples": len(benign), "min_samples": self.min_samples,
                "limits": {"psi": PSI_LIMIT, "drift_fraction": DRIFT_FRACTION},
                "recent_class_mix": dict(classes.most_common())}
        if len(benign) < self.min_samples:
            return {**base, "status": "insufficient_data", "drifted_features": [], "drifted_fraction": None}
        live = np.vstack(benign)
        rows = []
        for j, name in enumerate(feature_names):
            edges, expected = reference["edges"][j], reference["fractions"][j]
            if max(expected) >= 0.999:  # constant in training (e.g. time of day): no reference distribution
                continue
            counts = np.bincount(_bin_index(live[:, j], edges), minlength=len(edges) + 1)
            rows.append({"feature": name, "psi": round(psi(expected, counts / len(live)), 4)})
        drifted = [r["feature"] for r in rows if r["psi"] > PSI_LIMIT]
        fraction = len(drifted) / max(1, len(rows))
        return {**base, "status": "drift" if fraction >= DRIFT_FRACTION else "ok",
                "informative_features": len(rows), "drifted_fraction": round(fraction, 4),
                "drifted_features": drifted, "top_shifts": sorted(rows, key=lambda r: -r["psi"])[:10]}
