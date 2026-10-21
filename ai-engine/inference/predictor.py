"""SentinelAI Inference Predictor"""
import os, sys, json, time, joblib, logging, hashlib
import numpy as np
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.features import FEATURE_NAMES, LABEL_NAMES, FEATURE_SCHEMA_VERSION, extract_features_from_record, classify_honeypot_session

from inference.errors import ModelUnavailableError

log = logging.getLogger("sentinel.predictor")

# IP reputation (AbuseIPDB) is enrichment owned by the backend (threatIntelService), off the inference path;
# the engine makes no outbound calls (L5). Results keep ipReputationScore=None for the response shape.

def _threshold_env(name, default):
    try:
        value = float(os.getenv(name, ""))
    except ValueError:
        return default
    return value if 0.0 < value <= 1.0 else default

BLOCK_THRESHOLD   = _threshold_env("BLOCK_THRESHOLD", 0.92)
# Alert line (MONITOR): a non-BENIGN prediction at or above it becomes a threat + alert in the backend.
# 0.90 = lowest line meeting the 0.1 % benign-alert target on the de-duplicated chronological validation
# split (0.097 %); on later traffic it measured 0.154 % with 78.6 % attack detection. The earlier 0.85 was
# chosen on duplicate-inflated data and measured 0.306 % once duplicates were removed. See
# docs/CRITICAL_FIXES_REPORT.md §2.5 (experiments/c2_dedup_eval/threshold_validation).
MONITOR_THRESHOLD = min(_threshold_env("ALERT_THRESHOLD", 0.90), BLOCK_THRESHOLD)
ANOMALY_THRESHOLD = -0.55
# Analyst review (H5): a flow the classifier calls BENIGN but the Isolation Forest finds anomalous is
# labelled "Unknown"; when its anomaly signal is at least this level the action is REVIEW (no threat, no
# block). 0.55 = lowest level with <= 0.5 % of benign flows queued on the de-duplicated chronological
# validation split (`day_holdout_eval.py --protocols review`); on later traffic it queued 0.033 % of benign
# flows but recovered only 2 of 2,254 attacks the classifier missed. The anomaly tier is a weak signal.
REVIEW_MIN_SIGNAL = _threshold_env("REVIEW_MIN_ANOMALY_SIGNAL", 0.55)

# Isolation Forest Boundary-Anchored Anomaly Transformation Constants
# Default 10th-percentile contamination decision boundary offset from isolation_forest_cicids training
IF_DEFAULT_OFFSET = -0.47402357424116837
# Anomaly severity scaling span: linear deflection span below the anomaly boundary to full saturation
IF_ANOMALY_SPAN   = 0.20


def anomaly_signal(if_score):
    """
    Isolation Forest score_samples() -> bounded anomaly signal in [0, 1], for scalars or numpy arrays.
    The boundary is ANOMALY_THRESHOLD, the same value that sets isAnomaly / the "Unknown" override, so a
    flow either is an anomaly (signal > 0) or is not (signal 0) — the graded signal previously started at
    the model's offset_ (~-0.474) while isAnomaly used -0.55, disagreeing on ~2.8 % of benign flows (M10).
    Measured on the C1 chronological split, detection and benign FPR are unchanged at the 0.70/0.85/0.92
    lines; see docs/MEDIUM_PRIORITY_FIXES_REPORT.md.
    """
    s = np.asarray(if_score, dtype=float)
    sig = np.where(np.isfinite(s) & (s < ANOMALY_THRESHOLD),
                   np.minimum((ANOMALY_THRESHOLD - np.nan_to_num(s, nan=0.0, posinf=0.0, neginf=0.0)) / IF_ANOMALY_SPAN, 1.0),
                   0.0)
    return float(np.round(sig, 4)) if sig.ndim == 0 else sig

def combine_threat_score(rf_s, if_sig, is_attack):
    """
    threatScore from classifier strength (rf_s) and the Isolation Forest signal (if_sig), both in [0, 1].
    The 0.7/0.3 blend alone capped a confidently classified attack at 0.7 x confidence when the IF saw an
    inlier, i.e. below the 0.70 threat line, hiding most correct detections (C3,
    docs/C1_EVALUATION_PLAN_AND_RESULTS.md). For attack classes the classifier's confidence is therefore
    a floor and the anomaly signal can only raise it; BENIGN flows keep the plain blend.
    Accepts scalars or numpy arrays (the C1 evaluation uses the vectorised form).
    """
    rf_s = np.asarray(rf_s, dtype=float)
    blend = 0.7 * rf_s + 0.3 * np.asarray(if_sig, dtype=float)
    score = np.where(is_attack, np.maximum(rf_s, blend), blend)
    return float(score) if score.ndim == 0 else score

# Severity follows the operating lines, so engine and backend agree (M1; backend/utils/severity.js):
# CRITICAL = at/above the block line, HIGH = at/above the alert line, MEDIUM = 0.50 up to the alert line.
SEVERITY_MEDIUM = 0.50

def score_to_severity(s):
    if s >= BLOCK_THRESHOLD: return "CRITICAL"
    if s >= MONITOR_THRESHOLD: return "HIGH"
    if s >= SEVERITY_MEDIUM: return "MEDIUM"
    return "LOW"

# Honeypot verdicts. Nobody legitimate uses a decoy, so every class except the rule's BENIGN (logged in,
# ran only harmless commands) sits near or above the alert line; the score rises with what the attacker did:
# credential guessing -> MONITOR, lateral movement -> MONITOR, payload download/execution and exfiltration
# -> BLOCK line (auto-block still requires the backend's autoBlockEnabled setting).
HONEYPOT_RULES_VERSION = "honeypot_rules_v2"  # v2: whole program names, no duration rule
HONEYPOT_RULE_SCORES = {
    "BENIGN":            0.40,
    "Port Scan":         0.75,
    "SSH Brute Force":   0.90,
    "Lateral Movement":  0.90,
    "RCE Attempt":       0.93,
    "Data Exfiltration": 0.95,
}
HONEYPOT_COMMAND_STEP = 0.01  # per command, non-BENIGN only, capped at 0.99

REGISTRY_FILE = "registry.json"
MODEL_TYPES = ("rf", "xgboost", "stacking")


def file_sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_registry(model_dir: Path):
    """
    models/registry.json pins the deployed artifacts:
      {"classifier": {"file", "type", "meta", "sha256"}, "anomaly": {"file", "meta", "sha256"}}
    Returns the parsed registry, or None when the file does not exist. Raises ValueError when it exists
    but is malformed, so a broken registry never silently falls back to a different model.
    """
    path = Path(model_dir) / REGISTRY_FILE
    if not path.exists():
        return None
    reg = json.loads(path.read_text(encoding="utf-8"))
    for role in ("classifier", "anomaly"):
        entry = reg.get(role)
        if not isinstance(entry, dict) or not entry.get("file") or not entry.get("sha256"):
            raise ValueError(f"Model registry entry '{role}' needs at least 'file' and 'sha256'")
        if Path(entry["file"]).name != entry["file"]:
            raise ValueError(f"Model registry entry '{role}' must name a file inside the model directory")
    if reg["classifier"].get("type", "rf") not in MODEL_TYPES:
        raise ValueError(f"Model registry classifier type must be one of {MODEL_TYPES}")
    return reg


class SentinelPredictor:
    def __init__(self, model_dir="models"):
        self.model_dir = Path(model_dir)
        self.rf = self.ifo = None
        self.rf_meta = self.if_meta = {}
        self.model_type = "rf"
        self._loaded = False
        self.explainer = None
        self.registry = None
        self._low_data_classes = set()
        self.load()

    def load(self):
        self._loaded = False
        # Priority order for classification model:
        # 1. rf_classifier_cicids_v2.pkl
        # 2. rf_classifier_cicids.pkl
        # 3. xgb_classifier_cicids_v2.pkl
        # 4. xgb_classifier_cicids.pkl
        # 5. rf_classifier_v2.1.pkl
        # 6. xgb_classifier.pkl
        # 7. stacking_classifier_cicids.pkl
        model_candidates = [
            ("rf_classifier_cicids_v2.pkl", "rf", "rf_classifier_cicids_v2_meta.json"),
            ("rf_classifier_cicids.pkl", "rf", "rf_classifier_cicids_meta.json"),
            ("xgb_classifier_cicids_v2.pkl", "xgboost", "xgb_classifier_cicids_v2_meta.json"),
            ("xgb_classifier_cicids.pkl", "xgboost", "xgb_classifier_cicids_meta.json"),
            ("rf_classifier_v2.1.pkl", "rf", "rf_classifier_v2.1_meta.json"),
            ("xgb_classifier.pkl", "xgboost", "xgb_classifier_meta.json"),
            ("stacking_classifier_cicids.pkl", "stacking", "stacking_classifier_cicids_meta.json"),
        ]
        
        clf_path = None
        meta_path = None
        # A registry pins exact files and hashes (M11). Without one, the legacy first-match order below
        # applies, where any stray .pkl earlier in the list silently becomes the deployed model.
        try:
            registry = load_registry(self.model_dir)
        except (ValueError, json.JSONDecodeError) as e:
            log.error(f"Model registry invalid; inference unavailable: {e}")
            return
        # L11: registry.json sits next to the pickles, so whoever can replace a pickle can also rewrite its hash.
        # MODEL_REGISTRY_SHA256, set outside the model volume (environment / secret store), anchors the registry.
        pinned_registry = (os.getenv("MODEL_REGISTRY_SHA256") or "").strip().lower()
        if pinned_registry:
            reg_path = self.model_dir / REGISTRY_FILE
            actual = file_sha256(reg_path) if reg_path.exists() else None
            if actual != pinned_registry:
                log.error("models/registry.json does not match MODEL_REGISTRY_SHA256; inference unavailable")
                return
        if registry:
            clf_entry, if_entry = registry["classifier"], registry["anomaly"]
            pinned = ((self.model_dir / clf_entry["file"], clf_entry["sha256"]),
                      (self.model_dir / if_entry["file"], if_entry["sha256"]))
            for path, expected in pinned:
                if not path.exists():
                    log.error(f"Registered model file missing: {path.name}; inference unavailable")
                    return
                actual = file_sha256(path)
                if actual != expected.lower():
                    log.error(f"Model hash mismatch for {path.name} (expected {expected[:12]}, got {actual[:12]}); "
                              "inference unavailable")
                    return
            # Pickles are only reliable under the scikit-learn version that wrote them; another version can
            # load silently and return wrong results. ALLOW_SKLEARN_MISMATCH=1 overrides (e.g. a deliberate upgrade).
            pinned_sklearn = registry.get("sklearn_version")
            import sklearn
            if pinned_sklearn and pinned_sklearn != sklearn.__version__ and \
                    os.getenv("ALLOW_SKLEARN_MISMATCH", "").lower() not in ("1", "true", "yes"):
                log.error(f"Models were registered under scikit-learn {pinned_sklearn} but {sklearn.__version__} is "
                          "installed; inference unavailable (use the pinned .venv / requirements.txt)")
                return
            self.model_type = clf_entry.get("type", "rf")
            clf_path = pinned[0][0]
            meta_path = self.model_dir / clf_entry["meta"] if clf_entry.get("meta") else None
            if_p = pinned[1][0]
            if_meta_p = self.model_dir / if_entry["meta"] if if_entry.get("meta") else None
            self.registry = {"classifier": clf_entry["file"], "classifierSha256": clf_entry["sha256"],
                             "anomaly": if_entry["file"], "anomalySha256": if_entry["sha256"], "verified": True,
                             "registryPinned": bool(pinned_registry)}
            log.info(f"Model registry: {clf_entry['file']} + {if_entry['file']} (sha256 verified)")
            model_candidates = []
        elif os.getenv("ALLOW_UNREGISTERED_MODELS", "").lower() in ("1", "true", "yes"):
            log.warning("No models/registry.json: ALLOW_UNREGISTERED_MODELS set, using the legacy first-match load order")
        else:
            # Without a registry the first matching file name would silently become production (M4), e.g. a
            # stray or duplicate .pkl. Refuse; register the intended files with training/register_model.py.
            log.error("No models/registry.json; refusing to guess which model is production "
                      "(run training/register_model.py, or set ALLOW_UNREGISTERED_MODELS=1 for development)")
            return
        for filename, mtype, meta_filename in model_candidates:
            cand_p = self.model_dir / filename
            if cand_p.exists():
                self.model_type = mtype
                clf_path = cand_p
                meta_path = self.model_dir / meta_filename
                log.info(f"Found model {filename}. Selecting {mtype} classifier...")
                break

        # Decide which isolation forest model to load: isolation_forest_cicids.pkl over isolation_forest_v1.4.pkl
        if registry:
            pass  # pinned above
        elif (self.model_dir / "isolation_forest_cicids.pkl").exists():
            if_p = self.model_dir / "isolation_forest_cicids.pkl"
            if_meta_p = self.model_dir / "isolation_forest_cicids_meta.json"
            log.info("Found isolation_forest_cicids.pkl. Selecting real-data isolation forest...")
        else:
            if_p = self.model_dir / "isolation_forest_v1.4.pkl"
            if_meta_p = self.model_dir / "isolation_forest_v1.4_meta.json"
            log.info("Defaulting to isolation_forest_v1.4.pkl...")

        if not clf_path or not clf_path.exists() or not if_p.exists():
            log.warning("Required models not found; inference is unavailable")
            return
            
        try:
            self.clf = joblib.load(clf_path)
            self.rf = self.clf  # Keep self.rf referencing self.clf for backwards compatibility
            self.ifo = joblib.load(if_p)
            
            if meta_path and meta_path.exists():
                with open(meta_path) as f:
                    self.rf_meta = json.load(f)
            if if_meta_p and if_meta_p.exists():
                with open(if_meta_p) as f:
                    self.if_meta = json.load(f)
                    
            for model, metadata in ((self.rf, self.rf_meta), (self.ifo, self.if_meta)):
                count = getattr(model, "n_features_in_", None)
                if isinstance(count, (int, np.integer)) and count != len(FEATURE_NAMES):
                    raise ValueError("Model input dimension does not match the feature schema")
                if metadata.get("n_features", len(FEATURE_NAMES)) != len(FEATURE_NAMES):
                    raise ValueError("Model metadata feature count mismatch")
                if metadata.get("feature_names", FEATURE_NAMES) != FEATURE_NAMES:
                    raise ValueError("Model metadata feature order mismatch")
            # P5: the pinned golden set must reproduce exactly before the models count as loaded
            golden_entry = (registry or {}).get("golden")
            if golden_entry:
                from inference.model_checks import verify_golden
                golden_path = self.model_dir / golden_entry["file"]
                if not golden_path.exists() or file_sha256(golden_path) != golden_entry["sha256"].lower():
                    log.error("Golden set missing or its hash does not match the registry; inference unavailable")
                    return
                ok, message = verify_golden(self.clf, self.ifo, json.loads(golden_path.read_text(encoding="utf-8")))
                if not ok:
                    log.error(f"Golden-set check failed: {message}; inference unavailable")
                    return
                log.info(f"Golden-set check passed: {message}")
                self.registry["goldenCheck"] = message
            elif registry:
                log.warning("Registry has no golden set; re-run training/register_model.py to add one")
            self._loaded = True
            log.info(f"Classifier loaded from {clf_path}")
            print(f"[STARTUP] Loaded classification model: {clf_path.name}")
            self.init_explainer()
            self._init_shadow_detectors()
            self._low_data_classes = {name for name, v in self.class_provenance().items()
                                      if v.get("sufficientTrainingData") is False}
        except Exception as e:
            log.error(f"Load error: {e}")

    def _init_shadow_detectors(self):
        self.enable_shadow_b2 = os.getenv("ENABLE_SHADOW_B2", "false").lower() in ("true", "1", "yes")
        self.shadow_b2 = None
        if self.enable_shadow_b2:
            try:
                from modular.volumetric_flood import VolumetricFloodDetector
                self.shadow_b2 = VolumetricFloodDetector(
                    detector_id="shadow_b2_volumetric",
                    target_burst_pps_limit=1500.0,
                    target_surge_pps_limit=800.0,
                    target_unique_sources_limit=20
                )
                log.info("Initialized B2 VolumetricFloodDetector in shadow mode")
            except Exception as e:
                log.warning(f"Could not initialize shadow B2 detector: {e}")

        self.enable_shadow_e2 = os.getenv("ENABLE_SHADOW_E2", "false").lower() in ("true", "1", "yes")
        self.shadow_e2 = None
        if self.enable_shadow_e2:
            try:
                from modular.auth_event_adapter import AuthEventDetector
                self.shadow_e2 = AuthEventDetector(
                    detector_id="shadow_e2_auth",
                    warning_failures_5m=3,
                    critical_failures_1m=5,
                    critical_failures_5m=10,
                    credential_stuffing_users_threshold=4
                )
                log.info("Initialized E2 AuthEventDetector in shadow mode")
            except Exception as e:
                log.warning(f"Could not initialize shadow E2 detector: {e}")

    def init_explainer(self):
        if not self._loaded:
            return
        if self.model_type == "stacking":
            log.info("SHAP TreeExplainer is not supported for StackingClassifier. Explainability will return empty list.")
            self.explainer = None
            return
        try:
            import shap
            if self.model_type == "xgboost":
                tree_model = self.clf.named_steps["xgb"]
            else:
                tree_model = self.clf.named_steps["rf"]
            # Wrapped boosters (training.estimators.EncodedXGB) expose the fitted XGBClassifier as model_
            self.explainer = shap.TreeExplainer(getattr(tree_model, "model_", tree_model))
            log.info("SHAP TreeExplainer initialized successfully.")
        except Exception as e:
            log.warning(f"Could not initialize SHAP TreeExplainer (explain=True will fall back to empty): {e}")
            self.explainer = None

    def shap_for_classes(self, X, cls_pos):
        """|SHAP| of each row for the class it was assigned (rows x features), or None without an explainer."""
        if not self._loaded or self.explainer is None:
            return None
        raw = self.explainer.shap_values(self.clf.named_steps["scaler"].transform(X))
        rows = np.arange(len(X))
        if isinstance(raw, list):
            return np.abs(np.stack([raw[int(c)][i] for i, c in enumerate(cls_pos)]))
        raw = np.asarray(raw)
        if raw.ndim == 3:
            return np.abs(raw[rows, :, np.asarray(cls_pos, dtype=int)])
        return np.abs(raw)

    def calculate_if_anomaly_signal(self, if_score: float) -> float:
        """
        Transforms raw Isolation Forest score_samples() output to a bounded anomaly score in [0.0, 1.0].
        - Not anomalous (score_samples >= ANOMALY_THRESHOLD, i.e. isAnomaly False): returns 0.0
        - Anomalous: returns normalized deflection below ANOMALY_THRESHOLD in (0.0, 1.0]
        - Extreme outliers (deflection >= IF_ANOMALY_SPAN): saturates at 1.0
        Preserves anomaly direction, avoids artificial benign inflation, remains deterministic and bounded.
        """
        if if_score is None:
            return 0.0
        try:
            val = float(if_score)
            if np.isnan(val) or np.isinf(val):
                return 0.0
        except (ValueError, TypeError):
            return 0.0

        return anomaly_signal(val)

    def _classify(self, X):
        """
        One forest pass: (class label, probability row, column of that label). For sklearn/xgboost
        estimators predict() is the argmax of predict_proba(), so calling both ran the trees twice (L4).
        """
        proba = self.rf.predict_proba(X)[0]
        classes = getattr(self.rf, "classes_", None)
        if isinstance(classes, np.ndarray) and len(classes) == len(proba):
            pos = int(np.argmax(proba))
            return classes[pos], proba, pos
        label = self.rf.predict(X)[0]  # estimators without classes_ (test doubles)
        return label, proba, int(label)

    def get_explanation(self, record: dict, top_n=5, X=None, cls_pos=None) -> list:
        """SHAP contributions for the predicted class. predict() passes its feature vector and class column
        so the explanation does not re-extract features or run the classifier again."""
        if not self._loaded or self.explainer is None:
            return []
        try:
            import shap
            if X is None:
                X = extract_features_from_record(record).reshape(1,-1)
            X_scaled = self.clf.named_steps["scaler"].transform(X)
            cls = cls_pos if cls_pos is not None else self._classify(X)[2]
            
            raw_shap = self.explainer.shap_values(X_scaled)
            
            if isinstance(raw_shap, list):
                cls_shap = raw_shap[cls][0]
            elif isinstance(raw_shap, np.ndarray):
                if len(raw_shap.shape) == 3:
                    cls_shap = raw_shap[0, :, cls]
                else:
                    cls_shap = raw_shap[0]
            else:
                return []
                
            importance = []
            for name, val in zip(FEATURE_NAMES, cls_shap):
                importance.append({
                    "feature": name,
                    "contribution": float(val)
                })
            importance = sorted(importance, key=lambda x: abs(x["contribution"]), reverse=True)
            return importance[:top_n]
        except Exception as e:
            log.error(f"SHAP explanation error: {e}")
            return []

    def predict(self, record: dict, explain: bool = False) -> dict:
        return self.predict_many([record], explain=explain)[0]

    def _classify_many(self, X):
        """One forest pass for all rows: (labels, probability matrix, column of each label)."""
        proba = np.asarray(self.rf.predict_proba(X), dtype=float)
        if proba.ndim == 1:
            proba = proba.reshape(1, -1)
        classes = getattr(self.rf, "classes_", None)
        if isinstance(classes, np.ndarray) and len(classes) == proba.shape[1]:
            pos = proba.argmax(axis=1)
            return classes[pos], proba, pos
        labels = np.asarray(self.rf.predict(X)).reshape(-1)  # estimators without classes_ (test doubles)
        return labels, proba, labels.astype(int)

    def predict_many(self, records: list, explain: bool = False) -> list:
        """
        Score several flows with one classifier pass and one Isolation Forest pass (L12); /predict/batch
        previously ran both forests once per row. predict() is the one-row case of this method.
        """
        t0 = time.perf_counter()
        # Decoupled in Phase 2.4B: AbuseIPDB reputation is no longer queried synchronously during inference.
        # Threat intelligence enrichment executes asynchronously in backend threatIntelService.
        rep_score = None
        if not self._loaded:
            raise ModelUnavailableError("Required models are not loaded")
        if not records:
            return []
        X = np.vstack([extract_features_from_record(r).reshape(1, -1) for r in records])
        if not np.isfinite(X).all():
            raise ValueError("Features must be finite numbers")
        try:
            labels, proba, cls_pos = self._classify_many(X)
        except Exception as e:
            log.error(f"Prediction error: {e}")
            raise ModelUnavailableError("Classifier inference failed") from e
        try:
            if_scores = np.asarray(self.ifo.named_steps["if"].score_samples(self.ifo.named_steps["scaler"].transform(X)),
                                   dtype=float).reshape(-1)
        except Exception as e:
            raise ModelUnavailableError("Anomaly inference failed") from e
        per_row_ms = round((time.perf_counter() - t0) * 1000 / len(records), 2)
        return [self._assemble(record, X[i], labels[i], proba[i], int(cls_pos[i]), float(if_scores[i]),
                               per_row_ms, explain, rep_score)
                for i, record in enumerate(records)]

    def _assemble(self, record, x, cls, proba, cls_pos, if_score, ms, explain, rep_score):
        cname = LABEL_NAMES.get(int(cls), "BENIGN")
        probs = {LABEL_NAMES.get(i, f"c{i}"): round(float(p),4) for i,p in enumerate(proba)}
        max_p = float(max(proba))
        is_anomaly = if_score < ANOMALY_THRESHOLD
        rf_s   = max_p if cname != "BENIGN" else (1 - max_p)
        if_sig = self.calculate_if_anomaly_signal(if_score)
        score  = round(combine_threat_score(rf_s, if_sig, cname != "BENIGN"), 4)
        review = False
        if cname == "BENIGN" and is_anomaly:
            cname = "Unknown"; score = max(score, 0.55)
            review = if_sig >= REVIEW_MIN_SIGNAL

        explanation = []
        if explain:
            explanation = self.get_explanation(record, X=x.reshape(1, -1), cls_pos=cls_pos)

        # Shadow evaluation of B2 Volumetric Flood Detector (zero mutation of primary action/score)
        shadow_b2_eval = None
        if getattr(self, "shadow_b2", None) is not None:
            try:
                shadow_res = self.shadow_b2.evaluate(record)
                shadow_b2_eval = {
                    "decision": shadow_res.decision.value,
                    "status": shadow_res.status.value,
                    "rule": shadow_res.evidence.trigger_rule if shadow_res.evidence else None,
                    "confidence": shadow_res.confidence
                }
            except Exception as exc:
                log.debug(f"Shadow B2 evaluation failed safe: {exc}")

        action = "BLOCK" if score>=BLOCK_THRESHOLD else "MONITOR" if score>=MONITOR_THRESHOLD else "ALLOW"
        if review and action == "ALLOW":
            # The anomaly tier cannot raise an alert; it can only ask an analyst to look (never auto-block).
            action = "REVIEW"
        ret = {
            "predictedClass":cname,
            "threatScore":score,
            "severity":score_to_severity(score),
            "confidence":round(max_p,4),
            "isAnomaly":is_anomaly,
            "anomalyScore":round(if_score,4),
            "classProbabilities":probs,
            "inferenceTimeMs":ms,
            "action":action,
            "modelVersion":self.rf_meta.get("version","v2.1"),
            "featureImportance":explanation,
            "ipReputationScore": rep_score,
            "featureVector": [float(v) for v in x],
            "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
            # True when the predicted class had too few training rows for its verdicts to be trusted (H2)
            "lowTrainingDataClass": cname in self._low_data_classes,
        }
        if shadow_b2_eval is not None:
            ret["shadowB2"] = shadow_b2_eval
        return ret

    def predict_from_honeypot(self, session: dict) -> dict:
        # Cowrie sessions carry no packet-level flow data, so the verdict comes from the session rules
        # (utils.features.classify_honeypot_session) and HONEYPOT_RULE_SCORES. Running a rule-synthesised
        # flow through the CICIDS classifier scored every session type BENIGN (C1, docs/AI_ENGINE_STUDY_GUIDE.md).
        # The models are not used here; the readiness check is kept so the engine stays fail-closed as a whole.
        t0 = time.perf_counter()
        if not self._loaded:
            raise ModelUnavailableError("Required models are not loaded")
        # Decoupled in Phase 2.4B: AbuseIPDB reputation is no longer queried synchronously during inference.
        rep_score = None
        cname = classify_honeypot_session(session)
        n = len(session.get("commands", []))
        score = HONEYPOT_RULE_SCORES[cname]
        if cname != "BENIGN":
            score = round(min(score + n * HONEYPOT_COMMAND_STEP, 0.99), 4)

        # Shadow evaluation of E2 Structured Auth Event Adapter (zero mutation of primary action/score)
        shadow_e2_eval = None
        if getattr(self, "shadow_e2", None) is not None:
            try:
                auth_payload = {
                    "event_type": "AUTH_SUCCESS" if session.get("loginSucceeded") else "AUTH_FAILURE",
                    "src_ip": session.get("sourceIP", "0.0.0.0"),
                    "service": "ssh",
                    "timestamp": time.time(),
                    "raw_message": f"Honeypot session {session.get('sessionId')}: login {'succeeded' if session.get('loginSucceeded') else 'failed'} from {session.get('sourceIP')}"
                }
                shadow_res = self.shadow_e2.evaluate(auth_payload)
                shadow_e2_eval = {
                    "decision": shadow_res.decision.value,
                    "status": shadow_res.status.value,
                    "rule": shadow_res.evidence.trigger_rule if shadow_res.evidence else None,
                    "confidence": shadow_res.confidence
                }
            except Exception as exc:
                log.debug(f"Shadow E2 evaluation failed safe: {exc}")
        
        action = "BLOCK" if score >= BLOCK_THRESHOLD else "MONITOR" if score >= MONITOR_THRESHOLD else "ALLOW"
        # No model ran, so there is no classifier confidence or anomaly score to report.
        res = {"predictedClass": cname, "threatScore": score, "severity": score_to_severity(score),
               "confidence": None, "isAnomaly": False, "anomalyScore": None,
               "inferenceTimeMs": round((time.perf_counter() - t0) * 1000, 2), "action": action,
               "modelVersion": HONEYPOT_RULES_VERSION, "featureImportance": [],
               "ipReputationScore": rep_score, "classificationMethod": "honeypot_rules"}
        if shadow_e2_eval is not None:
            res["shadowE2"] = shadow_e2_eval
        return res

    def class_provenance(self) -> dict:
        """Per class the deployed classifier can output: what it was trained on and whether that is enough (H2)."""
        from utils.features import LABEL_SOURCES, MIN_TRAINING_ROWS
        classes = getattr(self.rf, "classes_", None) if self._loaded else None
        if classes is None:
            return {}
        counts = (self.rf_meta.get("class_counts") or {}).get("train", {})
        out = {}
        for c in classes:
            name = LABEL_NAMES.get(int(c), f"c{int(c)}")
            rows = counts.get(name)
            out[name] = {**LABEL_SOURCES.get(name, {}), "trainingRows": rows,
                         "sufficientTrainingData": None if rows is None else rows >= MIN_TRAINING_ROWS}
        return out

    def get_model_info(self):
        from utils.features import LABEL_MAP
        from inference.model_checks import read_history
        return {"lineage":read_history(self.model_dir, last=5),"classProvenance":self.class_provenance(),"modelsLoaded":self._loaded,"rfVersion":self.rf_meta.get("version","not loaded"),"ifVersion":self.if_meta.get("version","not loaded"),"rfMetrics":self.rf_meta.get("metrics",{}),"featureCount":len(FEATURE_NAMES),"thresholds":{"block":BLOCK_THRESHOLD,"monitor":MONITOR_THRESHOLD,"anomaly":ANOMALY_THRESHOLD,"reviewMinAnomalySignal":REVIEW_MIN_SIGNAL},"registry":self.registry}
