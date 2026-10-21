"""SentinelAI Inference Predictor"""
import os, sys, json, time, joblib, logging, requests, ipaddress, hashlib
import numpy as np
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.features import FEATURE_NAMES, LABEL_NAMES, FEATURE_SCHEMA_VERSION, extract_features_from_record, classify_honeypot_session

from inference.errors import ModelUnavailableError

log = logging.getLogger("sentinel.predictor")

# In-memory cache for IP reputation: ip_str -> (score, timestamp)
REPUTATION_CACHE = {}
CACHE_TTL = 3600  # 1 hour

def get_ip_reputation(ip_str: str) -> float:
    """
    Checks the IP reputation score via AbuseIPDB API.
    Returns a score between 0.0 and 1.0, or None (neutral/null) if lookup fails, is skipped, or is local.
    """
    if not ip_str:
        return None
        
    ip_str = ip_str.strip()
    
    # 1. Skip loopbacks and private IP ranges
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return None
    except ValueError:
        # Invalid IP string
        return None

    # 2. Check Cache & Prevent Unbounded Growth
    now = time.time()
    if len(REPUTATION_CACHE) > 5000:
        # Evict expired entries
        expired_keys = [k for k, (score, ts) in REPUTATION_CACHE.items() if now - ts >= CACHE_TTL]
        for k in expired_keys:
            del REPUTATION_CACHE[k]
        # If still too large, clear it entirely to reset memory footprint
        if len(REPUTATION_CACHE) > 5000:
            REPUTATION_CACHE.clear()
            log.info("Reputation cache size exceeded 5,000 entries. Flushed cache to prevent memory bloat.")

    if ip_str in REPUTATION_CACHE:
        score, timestamp = REPUTATION_CACHE[ip_str]
        if now - timestamp < CACHE_TTL:
            log.info(f"AbuseIPDB cache hit for {ip_str}: {score}")
            return score

    # 3. Query API
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        log.warning("ABUSEIPDB_API_KEY environment variable not set. Skipping reputation check.")
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_str,
        "maxAgeInDays": 90
    }

    try:
        log.info(f"Querying AbuseIPDB API for IP: {ip_str}")
        # Synchronous request with 3 second timeout
        response = requests.get(url, headers=headers, params=params, timeout=3.0)
        if response.status_code == 200:
            res_data = response.json()
            score_100 = res_data.get("data", {}).get("abuseConfidenceScore", 0)
            score = round(float(score_100) / 100.0, 4)
            # Update cache
            REPUTATION_CACHE[ip_str] = (score, now)
            log.info(f"AbuseIPDB reputation query successful for {ip_str}: {score}")
            return score
        else:
            log.warning(f"AbuseIPDB query failed with status {response.status_code}: {response.text}")
            return None
    except Exception as e:
        log.warning(f"AbuseIPDB query error for {ip_str}: {e}")
        return None

def _threshold_env(name, default):
    try:
        value = float(os.getenv(name, ""))
    except ValueError:
        return default
    return value if 0.0 < value <= 1.0 else default

BLOCK_THRESHOLD   = _threshold_env("BLOCK_THRESHOLD", 0.92)
# Alert line (MONITOR): a non-BENIGN prediction at or above it becomes a threat + alert in the backend.
# 0.85 = validation-selected line with a 2x margin for temporal drift: on the C1 validation split the
# point (0.79) and Wilson (0.80) rules met the 0.1 % benign-alert target but exceeded it on later traffic
# (0.134 % / 0.109 %); 0.85 had 0.046 % on validation. See docs/IMPROVEMENTS_REPORT.md.
MONITOR_THRESHOLD = min(_threshold_env("ALERT_THRESHOLD", 0.85), BLOCK_THRESHOLD)
ANOMALY_THRESHOLD = -0.55

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

def score_to_severity(s):
    if s >= 0.90: return "CRITICAL"
    if s >= 0.70: return "HIGH"
    if s >= 0.50: return "MEDIUM"
    return "LOW"

# Honeypot verdicts. Nobody legitimate uses a decoy, so every class except the rule's BENIGN (logged in,
# ran only harmless commands) sits near or above the alert line; the score rises with what the attacker did:
# credential guessing -> MONITOR, lateral movement -> MONITOR, payload download/execution and exfiltration
# -> BLOCK line (auto-block still requires the backend's autoBlockEnabled setting).
HONEYPOT_RULES_VERSION = "honeypot_rules_v1"
HONEYPOT_RULE_SCORES = {
    "BENIGN":            0.40,
    "Port Scan":         0.75,
    "SSH Brute Force":   0.86,
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
                             "anomaly": if_entry["file"], "anomalySha256": if_entry["sha256"], "verified": True}
            log.info(f"Model registry: {clf_entry['file']} + {if_entry['file']} (sha256 verified)")
            model_candidates = []
        else:
            log.warning("No models/registry.json: using first-match load order (run training/register_model.py)")
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
            self._loaded = True
            log.info(f"Classifier loaded from {clf_path}")
            print(f"[STARTUP] Loaded classification model: {clf_path.name}")
            self.init_explainer()
            self._init_shadow_detectors()
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
            self.explainer = shap.TreeExplainer(tree_model)
            log.info("SHAP TreeExplainer initialized successfully.")
        except Exception as e:
            log.warning(f"Could not initialize SHAP TreeExplainer (explain=True will fall back to empty): {e}")
            self.explainer = None

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
        t0 = time.perf_counter()
        # Decoupled in Phase 2.4B: AbuseIPDB reputation is no longer queried synchronously during inference.
        # Threat intelligence enrichment executes asynchronously in backend threatIntelService.
        rep_score = None
        if not self._loaded:
            raise ModelUnavailableError("Required models are not loaded")
        X = extract_features_from_record(record).reshape(1,-1)
        if not np.isfinite(X).all():
            raise ValueError("Features must be finite numbers")
        raw_vector = [float(v) for v in X[0]]
        try:
            cls, proba, cls_pos = self._classify(X)
            cname = LABEL_NAMES.get(int(cls), "BENIGN")
            probs = {LABEL_NAMES.get(i, f"c{i}"): round(float(p),4) for i,p in enumerate(proba)}
            max_p = float(max(proba))
        except Exception as e:
            log.error(f"Prediction error: {e}")
            raise ModelUnavailableError("Classifier inference failed") from e
        try:
            if_score  = float(self.ifo.named_steps["if"].score_samples(self.ifo.named_steps["scaler"].transform(X))[0])
            is_anomaly = if_score < ANOMALY_THRESHOLD
        except Exception as e:
            raise ModelUnavailableError("Anomaly inference failed") from e
        rf_s   = max_p if cname != "BENIGN" else (1 - max_p)
        if_sig = self.calculate_if_anomaly_signal(if_score)
        score  = round(combine_threat_score(rf_s, if_sig, cname != "BENIGN"), 4)
        if cname == "BENIGN" and is_anomaly:
            cname = "Unknown"; score = max(score, 0.55)
            
        explanation = []
        if explain:
            explanation = self.get_explanation(record, X=X, cls_pos=cls_pos)
            
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

        ms = round((time.perf_counter()-t0)*1000, 2)
        action = "BLOCK" if score>=BLOCK_THRESHOLD else "MONITOR" if score>=MONITOR_THRESHOLD else "ALLOW"
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
            "featureVector": raw_vector,
            "featureSchemaVersion": FEATURE_SCHEMA_VERSION
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

    def get_model_info(self):
        from utils.features import LABEL_MAP
        return {"modelsLoaded":self._loaded,"rfVersion":self.rf_meta.get("version","not loaded"),"ifVersion":self.if_meta.get("version","not loaded"),"rfMetrics":self.rf_meta.get("metrics",{}),"featureCount":len(FEATURE_NAMES),"thresholds":{"block":BLOCK_THRESHOLD,"monitor":MONITOR_THRESHOLD,"anomaly":ANOMALY_THRESHOLD},"registry":self.registry}
