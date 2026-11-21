"""
Honeypot-SESSION classifier: artifact format, safe loading, shadow inference and gated export (docs/SESSION_ML.md).

Separate from the network-flow model in every way: its own feature schema (session_ml.features, "session_v2"), its
own directory (SESSION_ML_MODEL_DIR, default ai-engine/models/session_ml/), its own manifest, and it never imports or
calls the CICIDS predictor. No artifact ships with the project: the labelled-data audit found no independent labels,
so the default state is MODEL_UNAVAILABLE and every result is shadow-only.

Artifact format "sentinel-session-logreg/1" is plain JSON (standardisation + logistic-regression coefficients). No
pickle / joblib / eval is ever used to load it, so a tampered file cannot execute code. Before use the artifact's
SHA-256 must match its manifest, the manifest's feature-schema version and feature names must match this engine's
exactly, every number must be finite, and the shapes must agree. Anything else is reported (INVALID_ARTIFACT /
INCOMPATIBLE_SCHEMA); there is no fallback to another model.

Modes (SESSION_ML_MODE): "shadow" (default) computes and reports; "off" reports DISABLED. There is no active mode:
a session prediction never changes the rule-based classification, a threat score, an alert or containment.
"""
import hashlib
import json
import math
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from session_ml import features as F

ARTIFACT_FORMAT = "sentinel-session-logreg/1"
MODEL_NAME = "session_classifier"
DEFAULT_DIR = Path(__file__).resolve().parent.parent / "models" / "session_ml"
MANIFEST = "manifest.json"
MAX_ARTIFACT_BYTES = 2_000_000
LOADABLE_STATUSES = ("shadow",)
EVIDENCE_SOURCES = ("operator", "external", "simulated", "unknown")
MODES = ("off", "shadow")

STATUS_OK = "OK"
STATUS_DISABLED = "DISABLED"
STATUS_UNAVAILABLE = "MODEL_UNAVAILABLE"
STATUS_INVALID = "INVALID_ARTIFACT"
STATUS_SCHEMA = "INCOMPATIBLE_SCHEMA"
STATUS_INPUT = "INVALID_INPUT"
STATUS_ERROR = "INFERENCE_ERROR"


class ArtifactError(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _finite_list(v, n=None) -> bool:
    return (isinstance(v, list) and (n is None or len(v) == n)
            and all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in v))


def load_artifact(model_dir: Path, allow_test_artifacts: bool = False) -> dict:
    """Validate and load a manifest + JSON model. Raises ArtifactError with a status and a reason."""
    model_dir = Path(model_dir)
    mpath = model_dir / MANIFEST
    if not mpath.is_file():
        raise ArtifactError(STATUS_UNAVAILABLE, f"no session-classifier manifest in {model_dir.name}/")
    try:
        if mpath.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ArtifactError(STATUS_INVALID, "manifest too large")
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ArtifactError(STATUS_INVALID, f"manifest unreadable ({type(e).__name__})")
    if not isinstance(manifest, dict):
        raise ArtifactError(STATUS_INVALID, "manifest is not an object")
    for key in ("name", "version", "status", "featureSchemaVersion", "artifact", "sha256", "format", "labels",
                "trainingData", "trainedAt", "evaluation"):
        if key not in manifest:
            raise ArtifactError(STATUS_INVALID, f"manifest lacks {key}")
    if manifest["name"] != MODEL_NAME or manifest["format"] != ARTIFACT_FORMAT:
        raise ArtifactError(STATUS_INVALID, "not a session-classifier artifact")
    status = manifest["status"]
    if status not in LOADABLE_STATUSES and not (allow_test_artifacts and status == "test_only"):
        raise ArtifactError(STATUS_INVALID, f"artifact status {status!r} is not loadable")
    if manifest["featureSchemaVersion"] != F.SCHEMA_VERSION:
        raise ArtifactError(STATUS_SCHEMA, f"artifact schema {manifest['featureSchemaVersion']!r} != {F.SCHEMA_VERSION!r}")
    name = str(manifest["artifact"])
    if "/" in name or "\\" in name or name.startswith("."):
        raise ArtifactError(STATUS_INVALID, "artifact name must be a plain file name in the model directory")
    apath = model_dir / name
    if not apath.is_file():
        raise ArtifactError(STATUS_INVALID, "artifact file missing")
    if apath.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ArtifactError(STATUS_INVALID, "artifact too large")
    if _sha256(apath) != manifest["sha256"]:
        raise ArtifactError(STATUS_INVALID, "artifact SHA-256 does not match the manifest")
    try:
        model = json.loads(apath.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ArtifactError(STATUS_INVALID, f"artifact unreadable ({type(e).__name__})")
    if not isinstance(model, dict) or model.get("format") != ARTIFACT_FORMAT:
        raise ArtifactError(STATUS_INVALID, "artifact format mismatch")
    if model.get("featureNames") != list(F.FEATURE_NAMES):
        raise ArtifactError(STATUS_SCHEMA, "artifact feature names differ from this engine's session schema")
    n = len(F.FEATURE_NAMES)
    classes = model.get("classes")
    if not (isinstance(classes, list) and len(classes) >= 2 and all(isinstance(c, str) and c for c in classes)
            and len(set(classes)) == len(classes)):
        raise ArtifactError(STATUS_INVALID, "classes must be 2+ distinct non-empty strings")
    coef, intercept = model.get("coef"), model.get("intercept")
    rows = 1 if len(classes) == 2 else len(classes)
    if not (isinstance(coef, list) and len(coef) == rows and all(_finite_list(r, n) for r in coef)
            and _finite_list(intercept, rows)):
        raise ArtifactError(STATUS_INVALID, "coefficient shapes or values are invalid")
    mean, scale = model.get("scalerMean"), model.get("scalerScale")
    if not (_finite_list(mean, n) and _finite_list(scale, n) and all(s > 0 for s in scale)):
        raise ArtifactError(STATUS_INVALID, "scaler shapes or values are invalid")
    if set(manifest["labels"]) != set(classes):
        raise ArtifactError(STATUS_INVALID, "manifest label definitions do not match the model classes")
    return {"manifest": manifest, "model": model}


def _scores(model: dict, x: List[float]) -> Dict[str, float]:
    z = [(v - m) / s for v, m, s in zip(x, model["scalerMean"], model["scalerScale"])]
    logits = [sum(c * v for c, v in zip(row, z)) + b for row, b in zip(model["coef"], model["intercept"])]
    classes = model["classes"]
    if len(classes) == 2:
        t = max(-500.0, min(500.0, logits[0]))
        p1 = 1.0 / (1.0 + math.exp(-t))
        return {classes[0]: 1.0 - p1, classes[1]: p1}
    top = max(logits)
    ex = [math.exp(v - top) for v in logits]
    total = sum(ex)
    return {c: e / total for c, e in zip(classes, ex)}


def _mode() -> str:
    raw = os.getenv("SESSION_ML_MODE", "shadow").strip().lower()
    return raw if raw in MODES else "shadow"  # an unknown value never enables anything beyond shadow


class SessionClassifier:
    def __init__(self, model_dir: Optional[Path] = None, allow_test_artifacts: bool = False):
        self.model_dir = Path(model_dir or os.getenv("SESSION_ML_MODEL_DIR") or DEFAULT_DIR)
        self.allow_test_artifacts = allow_test_artifacts
        self._lock = threading.Lock()
        self._loaded = None
        self._load_status = None
        self._load_reason = None
        self.reload()

    def reload(self):
        with self._lock:
            try:
                self._loaded = load_artifact(self.model_dir, self.allow_test_artifacts)
                self._load_status, self._load_reason = STATUS_OK, None
            except ArtifactError as e:
                self._loaded, self._load_status, self._load_reason = None, e.status, e.reason

    def status(self) -> dict:
        m = (self._loaded or {}).get("manifest") or {}
        return {
            "mode": _mode(), "shadowOnly": True, "featureSchemaVersion": F.SCHEMA_VERSION,
            "featureCount": len(F.FEATURE_NAMES),
            "modelStatus": self._load_status if _mode() != "off" else STATUS_DISABLED,
            "reason": self._load_reason,
            "modelName": m.get("name"), "modelVersion": m.get("version"), "artifactSha256": m.get("sha256"),
            "artifactStatus": m.get("status"), "calibrated": bool(m.get("calibrated", False)),
            "labels": sorted((m.get("labels") or {}).keys()) or None,
        }

    def classify(self, session) -> dict:
        """Shadow classification of one session. Never raises; never returns a prediction it did not compute."""
        sid = session.get("sessionId") if isinstance(session, dict) else None
        src = session.get("evidenceSource") if isinstance(session, dict) else None
        src = str(src).strip().lower() if src else "unknown"
        out = {
            "sessionId": str(sid)[:128] if sid not in (None, "") else None,
            "evidenceSource": src if src in EVIDENCE_SOURCES else "unknown",
            "mode": _mode(), "shadowOnly": True, "featureSchemaVersion": F.SCHEMA_VERSION,
            "modelName": None, "modelVersion": None, "prediction": None, "score": None, "scores": None,
            "calibrated": False, "reasonCodes": [], "quality": None, "status": None, "reason": None,
            "inferredAt": datetime.now(timezone.utc).isoformat(),
        }
        if out["mode"] == "off":
            out.update(status=STATUS_DISABLED, reason="SESSION_ML_MODE=off")
            return out
        if not isinstance(session, dict):
            out.update(status=STATUS_INPUT, reason="session is not an object")
            return out
        try:
            feats, quality = F.extract(session)
        except Exception as e:  # noqa: BLE001 - extraction is defensive; this is a last resort
            out.update(status=STATUS_INPUT, reason=f"feature extraction failed ({type(e).__name__})")
            return out
        out["reasonCodes"] = F.reason_codes(feats)
        out["quality"] = {k: (len(v) if isinstance(v, list) else v) for k, v in quality.items()}
        with self._lock:
            loaded, status, reason = self._loaded, self._load_status, self._load_reason
        if loaded is None:
            out.update(status=status or STATUS_UNAVAILABLE, reason=reason)
            return out
        m = loaded["manifest"]
        out.update(modelName=m["name"], modelVersion=m["version"], calibrated=bool(m.get("calibrated", False)))
        try:
            scores = _scores(loaded["model"], [feats[k] for k in F.FEATURE_NAMES])
            if not all(math.isfinite(v) and 0.0 <= v <= 1.0 for v in scores.values()) or \
                    abs(sum(scores.values()) - 1.0) > 1e-6:
                raise ValueError("model produced invalid scores")
        except Exception as e:  # noqa: BLE001
            out.update(status=STATUS_ERROR, reason=f"{type(e).__name__}: {str(e)[:120]}")
            return out
        best = max(sorted(scores), key=lambda c: scores[c])  # sorted first: ties break deterministically
        out.update(status=STATUS_OK, prediction=best, score=round(scores[best], 6),
                   scores={c: round(v, 6) for c, v in sorted(scores.items())})
        return out


_default = None
_default_lock = threading.Lock()


def default_classifier() -> SessionClassifier:
    global _default
    with _default_lock:
        if _default is None:
            _default = SessionClassifier()
        return _default


def reset_default():
    global _default
    with _default_lock:
        _default = None


# ── gated export (training) ──────────────────────────────────────────────────────────────────────────────────────
def _binary_aucs(y_true, scores, positive):
    """ROC-AUC (rank statistic) and PR-AUC (average precision) for one positive class; None if undefined."""
    pairs = sorted(zip(scores, [t == positive for t in y_true]), key=lambda p: -p[0])
    pos = sum(1 for _, t in pairs if t)
    neg = len(pairs) - pos
    if not pos or not neg:
        return None, None
    rank_sum, i = 0.0, 0
    asc = sorted(pairs, key=lambda p: p[0])
    while i < len(asc):
        j = i
        while j < len(asc) and asc[j][0] == asc[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2
        rank_sum += avg_rank * sum(1 for k in range(i, j) if asc[k][1])
        i = j
    roc = (rank_sum - pos * (pos + 1) / 2) / (pos * neg)
    tp, ap = 0, 0.0
    for k, (_, t) in enumerate(pairs, 1):
        if t:
            tp += 1
            ap += tp / k
    return round(roc, 4), round(ap / pos, 4)


def evaluate(y_true, y_pred, score_rows=None, classes=None) -> dict:
    from session_ml.pipeline import per_class_report
    rep = per_class_report(y_true, y_pred)
    recalls = [v["recall"] for c, v in rep["perClass"].items() if v["support"]]
    rep["balancedAccuracy"] = round(sum(recalls) / len(recalls), 4) if recalls else None
    rep["samples"] = len(y_true)
    rep["classDistribution"] = {c: sum(t == c for t in y_true) for c in sorted(set(y_true))}
    if score_rows is not None and classes and len(classes) == 2:
        roc, pr = _binary_aucs(y_true, [r[classes[1]] for r in score_rows], classes[1])
        rep["rocAuc"], rep["prAuc"], rep["positiveClass"] = roc, pr, classes[1]
    return rep


def export_model(rows: List[dict], out_dir: Path, rule_predict, version: str, label_definitions: Dict[str, str],
                 training_data: dict, force_for_tests: bool = False) -> dict:
    """Train a shadow candidate on INDEPENDENT labels (pipeline readiness gate), evaluate it on the later, source-
    disjoint test split against the rule baseline and a majority-class baseline, and write manifest + JSON model.

    Refuses when the readiness gate fails unless force_for_tests (then the artifact is marked "test_only", which the
    engine refuses to load). Refuses to write into the shipped models directory. Returns the manifest."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from session_ml import pipeline as P
    out_dir = Path(out_dir).resolve()
    shipped = (Path(__file__).resolve().parent.parent / "models").resolve()
    # Inside models/ only the dedicated session_ml/ directory, and never for a forced (test) export: the network-flow
    # artifacts, registry and Q-table seed beside it are never written.
    in_models = out_dir == shipped or shipped in out_dir.parents
    if in_models and (force_for_tests or out_dir != DEFAULT_DIR.resolve()):
        raise PermissionError("refusing to write into the shipped models directory")
    ready = P.readiness([{k: r[k] for k in ("sessionId", "label", "method", "startTime")} for r in rows])
    if not ready["ready"] and not force_for_tests:
        raise ValueError(f"readiness gate failed: {ready['reasons']}")
    if set(label_definitions) != {r["label"] for r in rows if r["method"] in P.INDEPENDENT_METHODS}:
        raise ValueError("label definitions must cover exactly the labelled classes")
    rows = [r for r in rows if r["method"] in P.INDEPENDENT_METHODS]
    train, test = P.time_aware_split(rows)
    X = lambda rs: [F.vector(r["session"]) for r in rs]  # noqa: E731
    scaler = StandardScaler().fit(X(train))
    clf = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=0)
    clf.fit(scaler.transform(X(train)), [r["label"] for r in train])
    model = {"format": ARTIFACT_FORMAT, "featureNames": list(F.FEATURE_NAMES),
             "scalerMean": [float(v) for v in scaler.mean_],
             "scalerScale": [float(v) if v > 0 else 1.0 for v in scaler.scale_],
             "classes": [str(c) for c in clf.classes_],
             "coef": [[float(v) for v in row] for row in clf.coef_], "intercept": [float(v) for v in clf.intercept_]}
    y_true = [r["label"] for r in test]
    score_rows = [_scores(model, F.vector(r["session"])) for r in test]
    cand = [max(sorted(s), key=lambda c: s[c]) for s in score_rows]
    majority = max(sorted({r["label"] for r in train}), key=lambda c: sum(r["label"] == c for r in train))
    evaluation = {
        "split": "time-aware, source-disjoint (pipeline.time_aware_split); test set not used for fitting or selection",
        "trainSessions": len(train), "testSessions": len(test),
        "candidate": evaluate(y_true, cand, score_rows, model["classes"]),
        "ruleBaseline": evaluate(y_true, [rule_predict(r["session"]) for r in test]),
        "majorityBaseline": evaluate(y_true, [majority] * len(test)),
        "readiness": ready,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    art = out_dir / "model.json"
    art.write_text(json.dumps(model, indent=1, sort_keys=True), encoding="utf-8")
    manifest = {"name": MODEL_NAME, "version": version, "status": "test_only" if force_for_tests else "shadow",
                "format": ARTIFACT_FORMAT, "featureSchemaVersion": F.SCHEMA_VERSION, "artifact": art.name,
                "sha256": _sha256(art), "labels": label_definitions, "trainingData": training_data,
                "trainedAt": datetime.now(timezone.utc).isoformat(), "evaluation": evaluation, "calibrated": False,
                "algorithm": "standardised logistic regression (class_weight=balanced, random_state=0)"}
    (out_dir / MANIFEST).write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest
