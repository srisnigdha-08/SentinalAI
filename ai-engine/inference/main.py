"""SentinelAI FastAPI Inference Server"""
import os, sys, time, logging, secrets, threading, hashlib
import numpy as np
from pathlib import Path
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Union
from collections import OrderedDict, defaultdict, deque
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, model_validator
import httpx, asyncio
sys.path.insert(0, str(Path(__file__).parent.parent))
ENGINE_ROOT = Path(__file__).resolve().parent.parent
# Load ai-engine/.env before importing the predictor (its thresholds read the environment at import),
# never overriding variables already set. Skipped under pytest so a developer's local .env cannot leak
# into the test suite's controlled environment.
if "pytest" not in sys.modules:
    from dotenv import load_dotenv
    load_dotenv(ENGINE_ROOT / ".env", override=False)
from inference.predictor import SentinelPredictor, MONITOR_THRESHOLD
from inference import deception
from inference.deception import get_scorer, save_scorer
from inference.errors import ModelUnavailableError
from monitoring.drift import DriftMonitor
from utils.features import FEATURE_NAMES, CANDIDATES, LABEL_NAMES, FEATURE_SCHEMA_VERSION
from utils.numeric import parse_strict_number

def pred_label(cls: int) -> str:
    return LABEL_NAMES.get(cls, f"c{cls}")
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.exceptions import RequestValidationError

import contextvars, re, uuid
# Correlation id of the request being handled (from the backend's X-Request-Id), added to every log line.
request_id_var = contextvars.ContextVar("request_id", default="-")

class _RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_var.get()
        return True

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s")
for _handler in logging.getLogger().handlers:
    _handler.addFilter(_RequestIdFilter())
log = logging.getLogger("sentinel.api")
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

# Relative MODEL_DIR is resolved against ai-engine/, not the shell's CWD, so the loaded model
# does not depend on where uvicorn was started (repo root has a different models/ copy).
_model_dir  = Path(os.getenv("MODEL_DIR") or ENGINE_ROOT / "models")
MODEL_DIR   = str(_model_dir if _model_dir.is_absolute() else ENGINE_ROOT / _model_dir)
BACKEND_API = os.getenv("SENTINEL_API", "http://localhost:5000/api")
API_KEY     = os.getenv("SENTINEL_KEY")
if not API_KEY:
    log.error("CRITICAL: SENTINEL_KEY environment variable is missing. Failing closed.")
    raise RuntimeError("Configuration error: SENTINEL_KEY environment variable is missing.")

# Engine-side "threat" counter and backend callback line. Defaults to the alert line so /model/stats and
# /predict callbacks count what the backend turns into threats (M1); SCORE_THRESHOLD still overrides.
THRESHOLD   = float(os.getenv("SCORE_THRESHOLD") or MONITOR_THRESHOLD)

predictor = None
stats = {"total":0,"threats":0,"blocked":0,"start":datetime.now(timezone.utc).isoformat(),"scores":deque(maxlen=100),"times":deque(maxlen=100),"classes":defaultdict(int),"time_sum_ms":0.0,
         "actions":defaultdict(int),"score_buckets":defaultdict(int),"score_sum":0.0,"incomplete":0}
# threatScore histogram buckets (P4): the 0.90 alert and 0.92 block lines get their own edges
SCORE_BUCKETS = (0.1, 0.3, 0.5, 0.7, 0.9, 0.92, 0.99)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global predictor
    predictor = SentinelPredictor(model_dir=MODEL_DIR)
    log.info("Inference model state: " + ("ready" if predictor._loaded else "unavailable"))
    yield
    try:
        with _scorer_lock:
            saved = save_scorer()
        if saved:
            log.info("Deception Q-table successfully flushed to disk on shutdown.")
        else:
            log.debug("Deception state was not initialized; no learning-state write.")
    except Exception as e:
        log.warning(f"Failed to flush Q-table on shutdown: {e}")

app = FastAPI(title="SentinelAI Inference Engine", version="2.1.0", lifespan=lifespan)

@app.middleware("http")
async def request_id_middleware(request, call_next):
    incoming = request.headers.get("x-request-id", "")
    request_id = incoming if _VALID_REQUEST_ID.match(incoming) else uuid.uuid4().hex
    token = request_id_var.set(request_id)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)
    response.headers["X-Request-Id"] = request_id
    return response

# Honeypot-session payloads carry attacker-typed command text; bound them before parsing (docs/SESSION_ML.md).
MAX_HONEYPOT_SESSION_BYTES = 2_000_000
# Rank 8: the same ceiling for every other request body (they had none). The largest legitimate body is
# /predict/batch (at most 500 records, about 1.2 MB).
MAX_REQUEST_BODY_BYTES = 2_000_000
HONEYPOT_SESSION_PATHS = ("/predict/honeypot", "/deception/score")


class BodySizeLimit:
    """Rank 8: enforce the body limit on the bytes actually received, not on Content-Length alone.

    The previous check trusted Content-Length, so a chunked body (no length), a false small length or a malformed
    header passed unchecked. This ASGI middleware: rejects a valid declared length over the limit before reading
    anything (413); refuses a malformed or negative Content-Length (400); otherwise reads the body, counting bytes,
    and answers 413 as soon as the count exceeds the limit, without reading further, so it never holds more than the
    limit in memory. A body within the limit is replayed to the application unchanged."""

    def __init__(self, app, limit=MAX_REQUEST_BODY_BYTES, session_limit=MAX_HONEYPOT_SESSION_BYTES):
        self.app, self.limit, self.session_limit = app, limit, session_limit

    @staticmethod
    async def _reject(send, status, error, limit=None):
        import json as _json
        detail = {"error": error}
        if limit is not None:
            detail["limitBytes"] = limit
        body = _json.dumps({"detail": detail}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") in ("GET", "HEAD", "OPTIONS", "DELETE"):
            return await self.app(scope, receive, send)
        session = scope.get("path", "").startswith(HONEYPOT_SESSION_PATHS)
        limit = self.session_limit if session else self.limit
        error = "SESSION_TOO_LARGE" if session else "REQUEST_TOO_LARGE"
        declared = [v for k, v in scope.get("headers", []) if k.lower() == b"content-length"]
        if declared:
            raw = declared[-1].decode("latin-1").strip()
            if len(declared) > 1 and len({d.strip() for d in declared}) > 1 or not raw.isdigit():
                return await self._reject(send, 400, "INVALID_CONTENT_LENGTH")
            if int(raw) > limit:
                return await self._reject(send, 413, error, limit)
        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > limit:
                return await self._reject(send, 413, error, limit)
            chunks.append(body)
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


app.add_middleware(BodySizeLimit)

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc):
    # Raw input may contain NaN/Infinity or captured credentials. Neither belongs in error JSON.
    detail = [{"loc": list(error["loc"]), "type": error["type"], "msg": error["msg"]}
              for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": detail})

CORS_ORIGINS = os.getenv("CORS_ORIGINS")
if CORS_ORIGINS:
    origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
else:
    origins = ["http://localhost:5000"]  # Restrict to Backend origin by default

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)

async def verify_api_key(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: Missing API Key")
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=403, detail="Forbidden: Invalid API Key")

# Swapping the served model is an administrative action, so it can require a second secret that only the
# backend's admin-gated route holds (M9). When SENTINEL_ADMIN_KEY is unset the service key alone is accepted
# (backwards compatible) and a warning is logged at startup.
ADMIN_KEY = os.getenv("SENTINEL_ADMIN_KEY") or None
if ADMIN_KEY is None:
    log.warning("SENTINEL_ADMIN_KEY not set: POST /model/reload accepts the shared service key alone")

async def verify_admin_key(x_api_key: str = Header(None), x_admin_key: str = Header(None)):
    await verify_api_key(x_api_key)
    if ADMIN_KEY is not None and not (x_admin_key and secrets.compare_digest(x_admin_key, ADMIN_KEY)):
        raise HTTPException(status_code=403, detail="Forbidden: model reload requires the admin key")

def _norm_key(k) -> str:
    return str(k).strip().lower().replace("_", "").replace(" ", "").replace("/", "")

# Every spelling extract_features_from_record would accept for a feature, so a bad value cannot fall back to a default.
_NUMERIC_KEYS = frozenset(_norm_key(c) for name in FEATURE_NAMES for c in (name, *CANDIDATES.get(name, [])))

class Record(BaseModel):
    sourceIP: str = "0.0.0.0"
    flow_duration: float = 1000.0
    total_fwd_packets: float = 1.0
    total_bwd_packets: float = 0.0
    total_len_fwd_packets: float = 60.0
    total_len_bwd_packets: float = 0.0
    fwd_packet_len_max: float = 60.0; fwd_packet_len_min: float = 60.0
    fwd_packet_len_mean: float = 60.0; fwd_packet_len_std: float = 0.0
    bwd_packet_len_max: float = 0.0; bwd_packet_len_min: float = 0.0
    bwd_packet_len_mean: float = 0.0; bwd_packet_len_std: float = 0.0
    flow_bytes_per_sec: float = 60000.0; flow_packets_per_sec: float = 1000.0
    flow_iat_mean: float = 1000.0; flow_iat_std: float = 0.0
    flow_iat_max: float = 1000.0; flow_iat_min: float = 1000.0
    fwd_iat_total: float = 0.0; fwd_iat_mean: float = 0.0; fwd_iat_std: float = 0.0
    fwd_iat_max: float = 0.0; fwd_iat_min: float = 0.0
    bwd_iat_total: float = 0.0; bwd_iat_mean: float = 0.0; bwd_iat_std: float = 0.0
    bwd_iat_max: float = 0.0; bwd_iat_min: float = 0.0
    fin_flag_count: float = 0.0; syn_flag_count: float = 1.0; rst_flag_count: float = 0.0
    psh_flag_count: float = 0.0; ack_flag_count: float = 0.0; urg_flag_count: float = 0.0
    fwd_psh_flags: float = 0.0; bwd_psh_flags: float = 0.0
    fwd_urg_flags: float = 0.0; bwd_urg_flags: float = 0.0
    fwd_header_len: float = 20.0; bwd_header_len: float = 0.0
    fwd_avg_bytes_per_bulk: float = 0.0; bwd_avg_bytes_per_bulk: float = 0.0
    timestamp: Optional[Union[str, float, int]] = None
    model_config = ConfigDict(extra="allow", allow_inf_nan=False)

    @model_validator(mode="before")
    @classmethod
    def finite_features(cls, values):
        if isinstance(values, dict):
            for key, value in values.items():
                # Aliases too: a CSV-named NaN/Infinity must be rejected, not silently replaced by a default.
                if _norm_key(key) in _NUMERIC_KEYS and parse_strict_number(value) is None:
                    raise ValueError(f"{key} must be a finite number")
        return values

class SessionData(BaseModel):
    sessionId: str = ""; sourceIP: str = "0.0.0.0"
    durationSeconds: float = Field(default=0.0, ge=0, allow_inf_nan=False); loginSucceeded: bool = False
    commands: List[Dict] = Field(default_factory=list, max_length=10000); iocCount: int = Field(default=0, ge=0); deceptionProfile: str = "centos_7"
    # Failed logins in this session and in the same source's recent sessions (brute-force rule, H4)
    failedLogins: int = Field(default=0, ge=0); recentFailedLogins: int = Field(default=0, ge=0)
    startTime: Optional[Union[str, float, int]] = None
    timestamp: Optional[Union[str, float, int]] = None
    model_config = ConfigDict(extra="allow")

def _alias_fields(record: "Record") -> set:
    """Schema fields the caller sent under another recognised name (e.g. CICFlowMeter's "Flow Duration")."""
    sent = {_norm_key(k) for k in (record.model_extra or {})}
    return {f for f in Record.model_fields if f not in record.model_fields_set
            and any(_norm_key(c) in sent for c in CANDIDATES.get(f, []) if c != f)}

def _record_payload(record: "Record") -> dict:
    """
    Feature payload for the predictor. A Record default (flow_duration=1000, ...) must not shadow a value the
    caller sent under an alias: extract_features_from_record tries the snake_case key first, so the default is
    dropped and the alias is used (H4, docs/AI_ENGINE_STUDY_GUIDE.md).
    """
    payload = record.model_dump()
    for field in _alias_fields(record):
        payload.pop(field, None)
    return payload

# Computed by the engine (entropy) or absent from CICIDS2017 (time of day): never expected from the caller.
_NOT_SENT_BY_CALLERS = ("payload_entropy", "time_of_day_sin", "time_of_day_cos")
# More defaulted raw features than this marks the input incomplete (M2). Training rows never had a missing
# feature, so a defaulted feature is fabricated; such a score may still alert, but it never auto-blocks.
MAX_DEFAULTED_FEATURES = int(os.getenv("MAX_DEFAULTED_FEATURES", "5"))
# Missing fields whose serving default is an invented non-zero measurement: any one makes the input incomplete.
# Known limit: up to MAX_DEFAULTED_FEATURES missing fields that default to 0 still count as complete and stay eligible
# for BLOCK, even though training never had a missing value. A value of 0 that the caller sent is not missing.
FABRICATED_DEFAULT_FEATURES = frozenset({
    "flow_duration", "total_fwd_packets", "total_len_fwd_packets", "fwd_packet_len_max", "fwd_packet_len_min",
    "fwd_packet_len_mean", "flow_bytes_per_sec", "flow_packets_per_sec", "flow_iat_mean", "flow_iat_max",
    "flow_iat_min", "syn_flag_count", "fwd_header_len",
})

def _defaulted_features(record: "Record") -> list:
    """Raw schema features the caller did not send under any recognised name (filled with defaults or 0)."""
    sent = set(record.model_fields_set) | {_norm_key(k) for k in (record.model_extra or {})}
    return [f for f in FEATURE_NAMES if f not in _NOT_SENT_BY_CALLERS and f not in sent
            and not any(_norm_key(c) in sent for c in CANDIDATES.get(f, [f]))]

def _score(record: "Record", explain: bool = False) -> dict:
    """predictor.predict plus the input-completeness policy (M2)."""
    return _input_policy(predictor.predict(_record_payload(record), explain=explain), record)

def _input_policy(r: dict, record: "Record") -> dict:
    r["defaultedFeatures"] = _defaulted_features(record)
    r["incompleteInput"] = (len(r["defaultedFeatures"]) > MAX_DEFAULTED_FEATURES
                            or not FABRICATED_DEFAULT_FEATURES.isdisjoint(r["defaultedFeatures"]))
    if r["incompleteInput"] and r.get("action") == "BLOCK":
        r["action"] = "MONITOR"
        r["actionCappedReason"] = "incomplete_input"
    return r

def _public_result(r: dict) -> dict:
    if not isinstance(r, dict):
        return r
    return {k: v for k, v in r.items() if k not in ("featureVector", "featureSchemaVersion")}

# Inference endpoints are plain `def`, so FastAPI runs them in its threadpool instead of blocking the
# event loop with CPU-bound RF/IF/SHAP work. Shared mutable state is therefore guarded by locks.
_stats_lock = threading.Lock()
_scorer_lock = threading.Lock()

def _upd(r):
    with _stats_lock:
        _upd_unlocked(r)

drift_monitor = DriftMonitor()

# The backend retries /predict/internal on transient failures with the same X-Request-Id and payload; a retry
# whose first attempt already reached here must not be counted twice in stats/drift (L4). Keyed on request id
# plus feature vector, so distinct flows sent within one backend request are all counted.
_SEEN_DELIVERIES = OrderedDict()
_SEEN_LIMIT = 10000

def _first_delivery(result: dict) -> bool:
    vector = result.get("featureVector")
    if vector is None:
        return True
    key = (request_id_var.get(), hashlib.sha256(np.asarray(vector, dtype=float).tobytes()).hexdigest())
    with _stats_lock:
        if key in _SEEN_DELIVERIES:
            return False
        _SEEN_DELIVERIES[key] = True
        if len(_SEEN_DELIVERIES) > _SEEN_LIMIT:
            _SEEN_DELIVERIES.popitem(last=False)
    return True

def _upd_unlocked(r):
    # Only real flow vectors feed drift monitoring; honeypot results carry no featureVector.
    if r.get("featureVector") is not None:
        drift_monitor.record(r["featureVector"], r.get("predictedClass"))
    stats["total"]+=1; stats["scores"].append(r["threatScore"]); stats["times"].append(r.get("inferenceTimeMs",0))
    stats["time_sum_ms"] += float(r.get("inferenceTimeMs") or 0)
    stats["classes"][r["predictedClass"]]+=1
    stats["actions"][r.get("action") or "UNKNOWN"] += 1
    stats["score_sum"] += float(r["threatScore"])
    for edge in SCORE_BUCKETS:
        if r["threatScore"] <= edge:
            stats["score_buckets"][edge] += 1
    if r.get("incompleteInput"):
        stats["incomplete"] += 1
    if r["threatScore"]>=THRESHOLD: stats["threats"]+=1
    if r["action"]=="BLOCK": stats["blocked"]+=1

async def _notify(result, ip):
    if result["threatScore"] < THRESHOLD: return
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            response = await c.post(f"{BACKEND_API}/ai/predictions", json={"inputSource":"network_traffic","sourceIP":ip,**result}, headers={"X-API-Key": API_KEY})
            response.raise_for_status()
    except Exception as exc:
        log.warning("Backend notification failed (%s)", type(exc).__name__)

@app.exception_handler(ModelUnavailableError)
async def model_unavailable_handler(request, exc):
    return JSONResponse(status_code=503, content={"detail": "Model inference unavailable"})

@app.get("/")
async def root():
    return {"service": app.title, "version": app.version, "status": "running",
            "health": "/health", "ready": "/ready", "docs": "/docs"}

@app.get("/ready")
async def ready():
    if not predictor or not predictor._loaded:
        raise HTTPException(503, "Required models are not loaded")
    return {"status": "ok"}

@app.get("/health")
async def health():
    return {"status":"ok","timestamp":datetime.now(timezone.utc).isoformat()}

@app.get("/model/info", dependencies=[Depends(verify_api_key)])
async def model_info():
    if not predictor: raise HTTPException(503,"Not ready")
    return {**predictor.get_model_info(), "deception": _deception_status()}

def _metrics_allowed(request) -> bool:
    token = os.getenv("METRICS_TOKEN")
    if token:
        return secrets.compare_digest(request.headers.get("authorization", ""), f"Bearer {token}")
    return (request.client.host if request.client else "") in ("127.0.0.1", "::1")

@app.get("/metrics")
def metrics(request: Request):
    """Prometheus text format: bearer METRICS_TOKEN when set, otherwise loopback only."""
    if not _metrics_allowed(request):
        raise HTTPException(403, "Metrics access denied")
    with _stats_lock:
        total, threats, time_sum = stats["total"], stats["threats"], stats["time_sum_ms"]
        classes, actions = dict(stats["classes"]), dict(stats["actions"])
        buckets, score_sum, incomplete = dict(stats["score_buckets"]), stats["score_sum"], stats["incomplete"]
    lines = ["# HELP sentinel_ai_predictions_total Predictions served, by class", "# TYPE sentinel_ai_predictions_total counter"]
    lines += [f'sentinel_ai_predictions_total{{class="{c.replace(chr(34), "_")}"}} {n}' for c, n in classes.items()]
    lines += ["# HELP sentinel_ai_threat_predictions_total Predictions at or above SCORE_THRESHOLD",
              "# TYPE sentinel_ai_threat_predictions_total counter", f"sentinel_ai_threat_predictions_total {threats}",
              "# HELP sentinel_ai_inference_ms_sum Total inference time (ms)", "# TYPE sentinel_ai_inference_ms_sum counter",
              f"sentinel_ai_inference_ms_sum {round(time_sum, 3)}",
              "# HELP sentinel_ai_inference_count Inferences timed", "# TYPE sentinel_ai_inference_count counter",
              f"sentinel_ai_inference_count {total}",
              "# HELP sentinel_ai_model_loaded 1 when the registered models are loaded", "# TYPE sentinel_ai_model_loaded gauge",
              f"sentinel_ai_model_loaded {1 if predictor and predictor._loaded else 0}"]
    # Prediction distribution (P4): what the engine decides and how its scores are spread, so a silent model
    # failure (everything BENIGN, scores collapsing to 0 or saturating) is visible and alertable.
    lines += ["# HELP sentinel_ai_actions_total Predictions by action", "# TYPE sentinel_ai_actions_total counter"]
    lines += [f'sentinel_ai_actions_total{{action="{a}"}} {n}' for a, n in actions.items()]
    lines += ["# HELP sentinel_ai_threat_score Distribution of threatScore", "# TYPE sentinel_ai_threat_score histogram"]
    lines += [f'sentinel_ai_threat_score_bucket{{le="{edge}"}} {buckets.get(edge, 0)}' for edge in SCORE_BUCKETS]
    lines += [f'sentinel_ai_threat_score_bucket{{le="+Inf"}} {total}', f"sentinel_ai_threat_score_sum {round(score_sum, 4)}",
              f"sentinel_ai_threat_score_count {total}",
              "# HELP sentinel_ai_incomplete_input_total Flows scored with too many defaulted features",
              "# TYPE sentinel_ai_incomplete_input_total counter", f"sentinel_ai_incomplete_input_total {incomplete}"]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

@app.get("/model/drift", dependencies=[Depends(verify_api_key)])
def model_drift():
    """Drift of recently scored flows versus the training statistics stored in the model's scaler."""
    if not predictor or not predictor._loaded:
        raise HTTPException(503, "Not ready")
    meta = predictor.rf_meta if isinstance(getattr(predictor, "rf_meta", None), dict) else {}
    reference = meta.get("drift_reference")
    if isinstance(reference, dict) and reference.get("edges"):
        # PSI of benign-predicted flows vs. the benign training quantiles stored at train time (M7)
        report = drift_monitor.report_psi(reference, FEATURE_NAMES)
    else:
        scaler = predictor.clf.named_steps.get("scaler") if hasattr(predictor.clf, "named_steps") else None
        if scaler is None or not hasattr(scaler, "mean_"):
            raise HTTPException(501, "Deployed model exposes no training statistics")
        report = {"method": "scaler_mean_variance", **drift_monitor.report(scaler.mean_, scaler.var_, FEATURE_NAMES)}
    report["model"] = (predictor.registry or {}).get("classifier")
    return report

GLOBAL_SHAP_ROWS = 200
# Rank 8: the reference summary is a derived result, cached OUTSIDE the model directory (never inside models/).
GLOBAL_SHAP_CACHE_DIR = Path(os.getenv("GLOBAL_SHAP_CACHE_DIR") or (ENGINE_ROOT / "derived" / "global_shap"))
GLOBAL_SHAP_CONFIG = {"explainer": "shap.TreeExplainer", "statistic": "mean |SHAP| of each row's predicted class",
                      "topOverall": 10, "topPerClass": 5}


def _summarise_shap(X):
    labels, _, cls_pos = predictor._classify_many(X)
    contrib = predictor.shap_for_classes(X, cls_pos)
    names = [pred_label(int(c)) for c in labels]

    def top(rows, k):
        mean = rows.mean(axis=0)
        return [{"feature": FEATURE_NAMES[j], "mean_abs_shap": round(float(mean[j]), 6)} for j in np.argsort(-mean)[:k]]

    by_class = {}
    for name in sorted(set(names)):
        mask = np.array([n == name for n in names])
        by_class[name] = {"samples": int(mask.sum()), "top": top(contrib[mask], GLOBAL_SHAP_CONFIG["topPerClass"])}
    return {"samples": int(len(X)), "overall": top(contrib, GLOBAL_SHAP_CONFIG["topOverall"]), "by_class": by_class}


def _model_identity():
    # predictor.registry is the load summary: {"classifier": <file>, "classifierSha256": <hash>, ...}
    reg = predictor.registry or {}
    return {"modelSha256": reg.get("classifierSha256"), "modelFile": reg.get("classifier"),
            "modelVersion": predictor.rf_meta.get("version"), "featureSchemaVersion": FEATURE_SCHEMA_VERSION}


def _pinned_golden():
    """The golden-set pin from models/registry.json (read-only): {"file", "rows", "sha256"} or {}."""
    import json as _json
    try:
        return _json.loads((Path(MODEL_DIR) / "registry.json").read_text(encoding="utf-8")).get("golden") or {}
    except (OSError, ValueError):
        return {}


def reference_global_shap(cache_dir: Optional[Path] = None) -> dict:
    """Rank 8: reproducible global explanation over a fixed, versioned sample: the golden regression vectors pinned
    (by SHA-256) in models/registry.json. Cached as JSON keyed by model SHA-256, feature schema, golden-set SHA-256
    and SHAP configuration, so any change to those yields a new key (the stale result is never served). Read-only on
    the model directory."""
    import json as _json
    identity = _model_identity()
    golden = _pinned_golden()
    if not identity["modelSha256"] or not golden.get("file") or not golden.get("sha256"):
        raise HTTPException(501, "Registry pins no model or golden set: no reproducible reference sample")
    gpath = Path(MODEL_DIR) / golden["file"]
    raw = gpath.read_bytes()
    gsha = hashlib.sha256(raw).hexdigest()
    if gsha != golden["sha256"]:
        raise HTTPException(409, "Golden set does not match the hash pinned in the registry")
    key_src = _json.dumps({**identity, "goldenSha256": gsha, "config": GLOBAL_SHAP_CONFIG}, sort_keys=True)
    key = hashlib.sha256(key_src.encode()).hexdigest()[:24]
    cache_dir = Path(cache_dir or GLOBAL_SHAP_CACHE_DIR)
    path = cache_dir / f"global_shap_{key}.json"
    try:
        cached = _json.loads(path.read_text(encoding="utf-8"))
        prov = cached.get("provenance", {})
        if prov.get("cacheKey") == key and prov.get("modelSha256") == identity["modelSha256"]:
            return {**cached, "cache": "hit"}
    except (OSError, ValueError):
        pass
    gold = _json.loads(raw)
    X = np.asarray(gold["vectors"], dtype=float)
    result = {"scope": "reference", **_summarise_shap(X),
              "provenance": {**identity, "generatedAt": datetime.now(timezone.utc).isoformat(),
                             "sample": {"source": f"models/{golden['file']}", "sha256": gsha, "rows": int(len(X)),
                                        "seed": gold.get("seed"),
                                        "note": "fixed regression vectors pinned in models/registry.json; "
                                                "a reproducible reference, not a representative traffic sample"},
                             "shapConfig": GLOBAL_SHAP_CONFIG, "cacheKey": key, "persisted": True}}
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(_json.dumps(result, indent=1), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as e:
        result["provenance"]["persisted"] = False
        log.warning("Global SHAP reference not cached (%s)", type(e).__name__)
    return {**result, "cache": "miss"}


@app.get("/model/explain/global", dependencies=[Depends(verify_api_key)])
def model_explain_global(scope: str = "recent"):
    """
    U5: which features drive the model's verdicts (mean |SHAP| for each flow's assigned class, overall and per class).

    scope=recent (default, unchanged): the last GLOBAL_SHAP_ROWS scored flows from the in-memory drift window. It is
    EPHEMERAL: recomputed on demand, lost on restart (provenance.persisted = false).
    scope=reference (Rank 8): the reproducible, cached summary over the pinned golden set (reference_global_shap).
    """
    if not predictor or not predictor._loaded:
        raise HTTPException(503, "Not ready")
    if predictor.explainer is None:
        raise HTTPException(501, "Deployed model has no SHAP explainer")
    if scope not in ("recent", "reference"):
        raise HTTPException(422, "scope must be 'recent' or 'reference'")
    if scope == "reference":
        return reference_global_shap()
    vectors, _ = drift_monitor.recent(GLOBAL_SHAP_ROWS)
    prov = {**_model_identity(), "generatedAt": datetime.now(timezone.utc).isoformat(),
            "sample": {"source": f"last {GLOBAL_SHAP_ROWS} flows scored by this engine process (in memory)"},
            "shapConfig": GLOBAL_SHAP_CONFIG, "persisted": False}
    if not vectors:
        return {"scope": "recent", "samples": 0, "overall": [], "by_class": {}, "provenance": prov}
    return {"scope": "recent", **_summarise_shap(np.vstack(vectors)), "provenance": prov}

_reload_lock = threading.Lock()

@app.post("/model/reload", dependencies=[Depends(verify_admin_key)])
def model_reload():
    """
    Load the models pinned in models/registry.json into a new predictor and swap it in only if it loaded
    and verified. In-flight requests finish on the previous predictor; on failure nothing changes (409).
    """
    global predictor
    with _reload_lock:
        candidate = SentinelPredictor(model_dir=MODEL_DIR)
        if not candidate._loaded:
            raise HTTPException(409, "New models did not load or verify; still serving the previous model")
        previous = predictor.get_model_info() if predictor and predictor._loaded else None
        predictor = candidate
    log.info("Model reloaded: %s", candidate.registry)
    return {"success": True, "previous": previous, "current": candidate.get_model_info()}

@app.get("/model/stats", dependencies=[Depends(verify_api_key)])
async def model_stats():
    with _stats_lock:
        sc,it=list(stats["scores"]),list(stats["times"])
    return {"totalPredictions":stats["total"],"totalThreats":stats["threats"],"totalBlocked":stats["blocked"],"avgThreatScore":round(sum(sc)/len(sc),4) if sc else 0,"avgInferenceMs":round(sum(it)/len(it),2) if it else 0,"classCounts":dict(stats["classes"]),"uptimeStart":stats["start"]}

@app.post("/predict", dependencies=[Depends(verify_api_key)])
def predict(record: Record, bg: BackgroundTasks, explain: bool = False):
    if not predictor: raise HTTPException(503,"Not ready")
    r = _score(record, explain); _upd(r)
    bg.add_task(_notify, r, record.sourceIP)
    return {"success":True,"sourceIP":record.sourceIP,"result":_public_result(r),"timestamp":datetime.now(timezone.utc).isoformat()}

@app.post("/predict/internal", dependencies=[Depends(verify_api_key)])
def predict_internal(record: Record, explain: bool = False):
    """Backend-owned persistence: returns the raw vector and never calls back."""
    if not predictor: raise HTTPException(503, "Not ready")
    result = _score(record, explain)
    if _first_delivery(result):
        _upd(result)
    return {"success": True, "result": result}

def _session_ml_shadow(session: dict) -> dict:
    """Shadow session-ML classification (session_ml.classifier; docs/SESSION_ML.md). Separate from the network-flow
    model and from the rule result: it never changes predictedClass, threatScore, alerts or containment, and a failure
    here is reported, never raised."""
    try:
        from session_ml.classifier import default_classifier
        return default_classifier().classify(session)
    except Exception as e:  # noqa: BLE001
        log.warning("Session ML shadow classification failed (%s)", type(e).__name__)
        return {"status": "INFERENCE_ERROR", "reason": type(e).__name__, "shadowOnly": True, "prediction": None,
                "sessionId": (session.get("sessionId") or None) if isinstance(session, dict) else None}

@app.post("/predict/honeypot/internal", dependencies=[Depends(verify_api_key)])
def predict_honeypot_internal(session: SessionData):
    if not predictor: raise HTTPException(503, "Not ready")
    payload = session.model_dump()
    result = predictor.predict_from_honeypot(payload)
    _upd(result)
    # "result" is the unchanged rule-based classification; "sessionML" is the separate, shadow-only ML block.
    return {"success": True, "result": result, "sessionML": _session_ml_shadow(payload)}

@app.get("/session-ml/status", dependencies=[Depends(verify_api_key)])
def session_ml_status():
    """Read-only: mode, feature schema and model state of the honeypot-session classifier (never the flow model)."""
    from session_ml.classifier import default_classifier
    return {"success": True, "status": default_classifier().status()}

@app.post("/predict/eval", dependencies=[Depends(verify_api_key)])
def predict_eval(record: Record, explain: bool = False):
    """
    Isolated model evaluation endpoint for benchmark datasets (e.g. CICIDS2017).
    Executes full ML feature extraction, Random Forest classification, Isolation Forest
    anomaly detection, and ThreatScore calculation.
    GUARANTEE: Completely bypasses background notifications, database persistence,
    server-wide stats mutation, and automated containment.
    """
    if not predictor: raise HTTPException(503, "Not ready")
    r = _score(record, explain)
    return {"success":True,"evaluation":True,"sourceIP":record.sourceIP,"result":_public_result(r),"timestamp":datetime.now(timezone.utc).isoformat()}


class VectorExplainRequest(BaseModel):
    featureVector: List[float]
    featureSchemaVersion: str


@app.post("/explain/vector", dependencies=[Depends(verify_api_key)])
def explain_vector(req: VectorExplainRequest):
    """
    On-demand SHAP explanation of a feature vector this engine produced earlier (the backend sends the copy it
    stored with the prediction; clients never supply it). Re-scores the vector with the normal scoring path so the
    backend can confirm it reproduces the stored prediction. No stats, drift, callbacks or persistence.
    """
    if not predictor: raise HTTPException(503, "Not ready")
    if req.featureSchemaVersion != FEATURE_SCHEMA_VERSION:
        raise HTTPException(409, f"Feature schema {req.featureSchemaVersion!r} differs from the engine's {FEATURE_SCHEMA_VERSION!r}")
    try:
        r = predictor.explain_vector(req.featureVector)
    except ValueError as e:
        raise HTTPException(422, str(e))
    # No SHAP explainer is not an outage: answer 200 so the backend's circuit breaker (which counts 5xx) is not
    # tripped by explanation requests and threat scoring keeps working; the backend refuses with its own reason.
    r["explainerAvailable"] = bool(r["contributions"])
    return {"success": True, "result": r}


@app.post("/predict/batch", dependencies=[Depends(verify_api_key)])
def predict_batch(records: List[Record], bg: BackgroundTasks):
    if not predictor: raise HTTPException(503,"Not ready")
    if len(records)>500: raise HTTPException(400,"Max 500")
    results=[]
    # One classifier pass and one Isolation Forest pass for the whole batch (L12)
    scored = predictor.predict_many([_record_payload(rec) for rec in records]) if records else []
    for rec, r in zip(records, scored):
        r = _input_policy(r, rec); _upd(r); results.append({"sourceIP":rec.sourceIP,"result":_public_result(r)})
        if r["threatScore"]>=THRESHOLD: bg.add_task(_notify,r,rec.sourceIP)
    return {"success":True,"total":len(results),"threatCount":sum(1 for r in results if r["result"]["threatScore"]>=THRESHOLD),"results":results}

@app.post("/predict/honeypot", dependencies=[Depends(verify_api_key)])
def predict_honeypot(s: SessionData, bg: BackgroundTasks):
    if not predictor: raise HTTPException(503,"Not ready")
    r=predictor.predict_from_honeypot(s.model_dump()); _upd(r)
    bg.add_task(_notify,r,s.sourceIP)
    return {"success":True,"sessionId":s.sessionId,"sourceIP":s.sourceIP,"result":_public_result(r),"timestamp":datetime.now(timezone.utc).isoformat()}

# Last Q-learner initialisation failure. A failing get_scorer() used to surface as a bare 500, so the backend
# logged only "status code 500" and every session stayed unscored with no reason anywhere but this console.
_deception_error = None

def _deception_status() -> dict:
    scorer = deception._scorer
    return {"initialized": scorer is not None,
            "qTablePath": str(scorer.learner.q_table_path) if scorer is not None else None,
            "lastError": _deception_error}

def _deception_scorer():
    """get_scorer() with its failure reported: a 503 with the reason, logged once per attempt."""
    global _deception_error
    try:
        scorer = get_scorer()
    except Exception as e:
        _deception_error = f"{type(e).__name__}: {e}"
        log.error("Deception scorer unavailable: %s", _deception_error)
        raise HTTPException(503, detail={"error": "DECEPTION_SCORER_UNAVAILABLE", "reason": _deception_error})
    _deception_error = None
    return scorer

@app.post("/deception/score", dependencies=[Depends(verify_api_key)])
def deception_score(s: SessionData):
    with _scorer_lock:
        scorer = _deception_scorer()
        try:
            res = scorer.process_session(s.model_dump())
        except Exception as e:
            log.exception("Deception scoring failed for session %s", s.sessionId[:64])
            raise HTTPException(500, detail={"error": "DECEPTION_SCORING_FAILED", "reason": f"{type(e).__name__}: {e}"})
    return {"success": True, "result": res}

@app.get("/deception/stats", dependencies=[Depends(verify_api_key)])
def deception_stats():
    """Read-only learner statistics and evidence provenance (docs/QLEARNING_EVIDENCE.md). Draws no decision and
    changes nothing (unlike /deception/recommendation, which samples the exploration policy)."""
    from rl_engine.deception_scorer import SUPPORTED_PROFILES, UNSUPPORTED_PROFILES
    with _scorer_lock:
        scorer = _deception_scorer()
        stats = scorer.learner.get_stats()
        return {"success": True, "learnerStats": stats, "provenance": stats.get("provenance"),
                "v2Mode": scorer.v2_mode, "v2Activation": _v2_activation(scorer) if scorer.v2 is not None else None,
                "servablePersonas": list(SUPPORTED_PROFILES),
                "unsupportedPersonas": sorted(UNSUPPORTED_PROFILES)}


@app.get("/deception/recommendation", dependencies=[Depends(verify_api_key)])
def deception_recommendation(current: str = "centos_7"):
    """
    The persona to serve next, chosen epsilon-greedily from the Q-table with the currently served persona
    as state. Applying it is the honeypot host's job (honeypot/deception_rotator.py); nothing changes here.
    """
    from rl_engine.deception_scorer import PROFILES
    if current not in PROFILES:
        raise HTTPException(422, f"Unknown profile '{current}'")
    with _scorer_lock:
        scorer = _deception_scorer()
        learner = scorer.learner
        next_profile = learner.choose_action(current)
        greedy = learner.greedy_action(current)
        out = {"success": True, "current": current, "nextProfile": next_profile, "policy": learner.policy,
               "explored": next_profile != greedy, "learnerStats": learner.get_stats()}
        if scorer.v2 is not None:
            # Persona policy v2. Shadow: reported only, never applied (the backend reads nextProfile/policy/explored).
            # Active (DECEPTION_V2=active, the owner's switch) is fail-closed (rl_engine/v2_activation.py): v2 drives
            # nextProfile only if the newest Rank 6 readiness evidence is valid and READY; otherwise v1 serves.
            try:
                v2 = scorer.v2.stats(current)
            except Exception as e:  # noqa: BLE001 - v2 must never break v1 recommendations
                log.warning("Persona policy v2 recommendation failed (%s); serving v1", type(e).__name__)
                v2 = None
            if v2:
                # Only a servable persona is ever reported or applied; otherwise v1's pick stands.
                from rl_engine.persona_policy_v2 import validate_recommendation
                rec, status = validate_recommendation(v2.get("recommendation"))
                v2 = {**v2, "recommendation": rec, "status": status}
            activation = _v2_activation(scorer)
            out["v2Activation"] = activation
            if v2 and activation["allowed"] and v2["status"] == "OK":
                out.update({"nextProfile": v2["recommendation"], "policy": v2["policyVersion"], "explored": v2["explored"],
                            "policyV1": {"nextProfile": next_profile, "policy": learner.policy, "explored": next_profile != greedy}})
            elif v2:
                out["shadow"] = {"mode": "shadow", "applied": False, **v2}
        return out


_v2_last_block = None


def _v2_activation(scorer) -> dict:
    """The fail-closed activation decision. A blocked activation request is logged once per reason (the rotator
    polls this endpoint) and returned as v2Activation for diagnostics; it never raises."""
    global _v2_last_block
    try:
        from rl_engine.v2_activation import activation_decision
        d = activation_decision(scorer.v2_mode, getattr(scorer, "v2_readiness_dir", None))
    except Exception as e:  # noqa: BLE001 - fail closed
        d = {"allowed": False, "requested": scorer.v2_mode == "active", "readiness": None,
             "reason": f"READINESS_CHECK_ERROR:{type(e).__name__}"}
    if d.get("requested") and not d["allowed"]:
        if d["reason"] != _v2_last_block:
            log.warning("DECEPTION_V2=active requested but blocked (%s, readiness %s); v1 serves", d["reason"], d.get("readiness"))
            _v2_last_block = d["reason"]
    else:
        _v2_last_block = None
    return d

class AuthTelemetryRecord(BaseModel):
    # Typed and bounded (L2): optional fields are Optional, strings have length limits, numbers are finite.
    event_type: str = Field(default="AUTH_FAILURE", max_length=64)
    src_ip: str = Field(default="0.0.0.0", max_length=64)
    dst_ip: Optional[str] = Field(default=None, max_length=64)
    dst_port: int = Field(default=22, ge=0, le=65535)
    service: str = Field(default="ssh", max_length=64)
    user_identity: Optional[str] = Field(default=None, max_length=256)
    raw_message: Optional[str] = Field(default=None, max_length=4096)
    timestamp: Optional[float] = Field(default=None, allow_inf_nan=False)

@app.post("/predict/auth/shadow", dependencies=[Depends(verify_api_key)])
def predict_auth_shadow(auth_record: AuthTelemetryRecord):
    """
    Shadow-only endpoint for E2 structured authentication telemetry.
    Logs decisions in shadow mode without modifying production models, containment, or primary state.
    """
    if not predictor:
        raise HTTPException(503, "Not ready")
    if getattr(predictor, "shadow_e2", None) is None:
        return {"success": True, "shadow_enabled": False, "message": "Shadow E2 detector is disabled by feature flag"}
    try:
        res = predictor.shadow_e2.evaluate(auth_record.model_dump())
        return {
            "success": True,
            "shadow_enabled": True,
            "decision": res.decision.value,
            "severity": res.severity.value,
            "confidence": res.confidence,
            "rule": res.evidence.trigger_rule if res.evidence else None,
            "mitigation": res.mitigation_recommendation.watermark if res.mitigation_recommendation else None
        }
    except Exception as exc:
        # Never echo exception text (it can contain the submitted raw_message or internals) (L1)
        log.warning("Shadow E2 evaluation failed (%s)", type(exc).__name__)
        return {"success": False, "error": "shadow evaluation failed"}

if __name__ == "__main__":
    import uvicorn
    # Standalone development/diagnostic runner.
    # Default to loopback (127.0.0.1) for defense-in-depth so internal inference endpoints
    # are not inadvertently exposed across external network interfaces.
    # Note: Binding to a non-loopback interface (e.g. 0.0.0.0) exposes the service
    # to all reachable network interfaces and must be an intentional deployment choice.
    # CLI launches (`uvicorn inference.main:app --host ... --port ...`) and process managers
    # (e.g. systemd, Docker, gunicorn) do not execute __main__ and must be configured separately.
    host = os.getenv("AI_ENGINE_HOST", "127.0.0.1")
    # Specific AI_ENGINE_PORT is required; generic PORT (e.g. 5000 used by Node backend) is ignored
    # to prevent port collisions in shared environments.
    port = int(os.getenv("AI_ENGINE_PORT", "8000"))
    # Development auto-reload is configurable via AI_ENGINE_RELOAD; disabled by default
    # unless explicitly in development mode to avoid reload loops and file-watcher overhead.
    reload_env = os.getenv("AI_ENGINE_RELOAD")
    if reload_env is not None:
        reload = reload_env.lower() in ("1", "true", "yes")
    else:
        reload = os.getenv("SENTINEL_ENV", "").lower() == "development"
    uvicorn.run("inference.main:app", host=host, port=port, reload=reload)
