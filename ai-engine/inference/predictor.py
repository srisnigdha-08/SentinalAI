"""SentinelAI Inference Predictor"""
import os, sys, json, time, joblib, logging, requests, ipaddress
import numpy as np
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.features import FEATURE_NAMES, LABEL_NAMES, FEATURE_SCHEMA_VERSION, extract_features_from_record, extract_features_from_honeypot

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

BLOCK_THRESHOLD   = 0.92
MONITOR_THRESHOLD = 0.70
ANOMALY_THRESHOLD = -0.55

# Isolation Forest Boundary-Anchored Anomaly Transformation Constants
# Default 10th-percentile contamination decision boundary offset from isolation_forest_cicids training
IF_DEFAULT_OFFSET = -0.47402357424116837
# Anomaly severity scaling span: linear deflection span from inlier boundary (offset_) to extreme outlier saturation floor (-0.6740)
IF_ANOMALY_SPAN   = 0.20

def score_to_severity(s):
    if s >= 0.90: return "CRITICAL"
    if s >= 0.70: return "HIGH"
    if s >= 0.50: return "MEDIUM"
    return "LOW"

class SentinelPredictor:
    def __init__(self, model_dir="models"):
        self.model_dir = Path(model_dir)
        self.rf = self.ifo = None
        self.rf_meta = self.if_meta = {}
        self.model_type = "rf"
        self._loaded = False
        self.explainer = None
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
        for filename, mtype, meta_filename in model_candidates:
            cand_p = self.model_dir / filename
            if cand_p.exists():
                self.model_type = mtype
                clf_path = cand_p
                meta_path = self.model_dir / meta_filename
                log.info(f"Found model {filename}. Selecting {mtype} classifier...")
                break

        # Decide which isolation forest model to load: isolation_forest_cicids.pkl over isolation_forest_v1.4.pkl
        if (self.model_dir / "isolation_forest_cicids.pkl").exists():
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
        except Exception as e:
            log.error(f"Load error: {e}")

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
        - Inliers (score_samples >= offset, decision_function >= 0): returns 0.0
        - Outliers (score_samples < offset, decision_function < 0): returns normalized deflection in (0.0, 1.0]
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

        offset = IF_DEFAULT_OFFSET
        if self.ifo is not None and hasattr(self.ifo, "named_steps") and "if" in self.ifo.named_steps:
            offset = float(getattr(self.ifo.named_steps["if"], "offset_", IF_DEFAULT_OFFSET))

        if val >= offset:
            return 0.0

        deflection = offset - val
        return round(float(min(deflection / IF_ANOMALY_SPAN, 1.0)), 4)

    def get_explanation(self, record: dict, top_n=5) -> list:
        if not self._loaded or self.explainer is None:
            return []
        try:
            import shap
            X = extract_features_from_record(record).reshape(1,-1)
            X_scaled = self.clf.named_steps["scaler"].transform(X)
            cls = int(self.clf.predict(X)[0])
            
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
            cls   = self.rf.predict(X)[0]
            proba = self.rf.predict_proba(X)[0]
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
        score  = round(0.7*rf_s + 0.3*if_sig, 4)
        if cname == "BENIGN" and is_anomaly:
            cname = "Unknown"; score = max(score, 0.55)
            
        explanation = []
        if explain:
            explanation = self.get_explanation(record)
            
        ms = round((time.perf_counter()-t0)*1000, 2)
        action = "BLOCK" if score>=BLOCK_THRESHOLD else "MONITOR" if score>=MONITOR_THRESHOLD else "ALLOW"
        return {
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

    def predict_from_honeypot(self, session: dict) -> dict:
        t0 = time.perf_counter()
        X  = extract_features_from_honeypot(session).reshape(1,-1)
        n  = len(session.get("commands",[]))
        # Decoupled in Phase 2.4B: AbuseIPDB reputation is no longer queried synchronously during inference.
        rep_score = None
        if not self._loaded:
            raise ModelUnavailableError("Required models are not loaded")
        if not np.isfinite(X).all():
            raise ValueError("Features must be finite numbers")
        try:
            cls = self.rf.predict(X)[0]; proba=self.rf.predict_proba(X)[0]
            cname=LABEL_NAMES.get(int(cls),"SSH Brute Force"); max_p=float(max(proba))
        except Exception as e:
            raise ModelUnavailableError("Classifier inference failed") from e
        try:
            if_score=float(self.ifo.named_steps["if"].score_samples(self.ifo.named_steps["scaler"].transform(X))[0]); is_anomaly=if_score<ANOMALY_THRESHOLD
        except Exception as e:
            raise ModelUnavailableError("Anomaly inference failed") from e
        
        # Fixed: calculate rf_s correctly for BENIGN to scale down the threat score
        rf_s = max_p if cname != "BENIGN" else (1.0 - max_p)
        if_sig = self.calculate_if_anomaly_signal(if_score)
        base = 0.7 * rf_s + 0.3 * if_sig
        score = round(min(base + n*0.02, 0.99), 4)
        
        res = self._build(cname,score,max_p,is_anomaly,if_score,(time.perf_counter()-t0)*1000)
        res["ipReputationScore"] = rep_score
        return res

    def _build(self,cls,score,confidence,anomaly,if_score,ms):
        action="BLOCK" if score>=BLOCK_THRESHOLD else "MONITOR" if score>=MONITOR_THRESHOLD else "ALLOW"
        return {"predictedClass":cls,"threatScore":score,"severity":score_to_severity(score),"confidence":round(confidence,4),"isAnomaly":anomaly,"anomalyScore":round(if_score,4),"inferenceTimeMs":round(ms,2),"action":action,"modelVersion":self.rf_meta.get("version","v2.1"),"featureImportance":[]}

    def get_model_info(self):
        from utils.features import LABEL_MAP
        return {"modelsLoaded":self._loaded,"rfVersion":self.rf_meta.get("version","not loaded"),"ifVersion":self.if_meta.get("version","not loaded"),"rfMetrics":self.rf_meta.get("metrics",{}),"featureCount":len(FEATURE_NAMES),"thresholds":{"block":BLOCK_THRESHOLD,"monitor":MONITOR_THRESHOLD,"anomaly":ANOMALY_THRESHOLD}}
