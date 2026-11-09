"""
Golden-set check (P5) and registry history (U3).

Golden set: at registration, a fixed set of feature vectors is scored by the classifier and the Isolation Forest
and the outputs are stored in models/golden_set.json (pinned by SHA-256 in registry.json). At startup the engine
scores the same vectors again and refuses to serve if anything differs. This catches what hashes cannot: the
right pickle loaded under a different numpy/scikit-learn/xgboost build, or a silently broken environment.
It checks reproducibility of the artifact, not its accuracy.

History: every registration appends one line to models/registry_history.jsonl (append-only), so the lineage
of served models and the metrics they were promoted with survives each re-pin of registry.json.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

GOLDEN_FILE = "golden_set.json"
HISTORY_FILE = "registry_history.jsonl"
GOLDEN_ROWS = 20
GOLDEN_SEED = 20261021
GOLDEN_TOL = 1e-6


def golden_vectors(n_features: int) -> np.ndarray:
    """Deterministic, heavy-tailed flow-like vectors (no data files needed), plus an all-zero row."""
    rng = np.random.default_rng(GOLDEN_SEED)
    X = rng.lognormal(mean=3.0, sigma=2.5, size=(GOLDEN_ROWS - 1, n_features))
    return np.vstack([X, np.zeros((1, n_features))])


def golden_outputs(clf, ifo, X) -> dict:
    proba = np.asarray(clf.predict_proba(X), dtype=float)
    if_scores = np.asarray(ifo.named_steps["if"].score_samples(ifo.named_steps["scaler"].transform(X)), dtype=float)
    classes = np.asarray(getattr(clf, "classes_", np.arange(proba.shape[1])))
    return {"classes": [int(c) for c in classes[proba.argmax(axis=1)]],
            "proba": np.round(proba, 8).tolist(), "if_scores": np.round(if_scores, 8).tolist()}


def build_golden(clf, ifo, n_features: int) -> dict:
    X = golden_vectors(n_features)
    return {"created_at": datetime.now(timezone.utc).isoformat(), "seed": GOLDEN_SEED, "rows": len(X),
            "vectors": X.tolist(), "expected": golden_outputs(clf, ifo, X)}


def verify_golden(clf, ifo, golden: dict, tol: float = GOLDEN_TOL):
    """(ok, message). Classes must match exactly; probabilities and IF scores within tol."""
    X = np.asarray(golden["vectors"], dtype=float)
    got, want = golden_outputs(clf, ifo, X), golden["expected"]
    if got["classes"] != want["classes"]:
        bad = sum(a != b for a, b in zip(got["classes"], want["classes"]))
        return False, f"{bad}/{len(X)} golden predictions changed class"
    dp = float(np.max(np.abs(np.asarray(got["proba"]) - np.asarray(want["proba"]))))
    di = float(np.max(np.abs(np.asarray(got["if_scores"]) - np.asarray(want["if_scores"]))))
    if dp > tol or di > tol:
        return False, f"golden outputs drifted (max |dp|={dp:.2e}, max |d if|={di:.2e})"
    return True, f"{len(X)} golden rows reproduced"


def append_history(model_dir, registry: dict, source: str, note: str = None, metrics: dict = None) -> dict:
    """Append one registration record to models/registry_history.jsonl and return it."""
    record = {"registered_at": registry.get("registered_at") or datetime.now(timezone.utc).isoformat(),
              "source": source,
              "classifier": {k: registry["classifier"].get(k) for k in ("file", "type", "version", "sha256")},
              "anomaly": {k: registry["anomaly"].get(k) for k in ("file", "version", "sha256")},
              "sklearn_version": registry.get("sklearn_version")}
    if metrics:
        record["metrics"] = metrics
    if note:
        record["note"] = note
    with open(Path(model_dir) / HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record


def read_history(model_dir, last: int = 10) -> list:
    path = Path(model_dir) / HISTORY_FILE
    if not path.exists():
        return []
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    out = []
    for line in lines[-last:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
