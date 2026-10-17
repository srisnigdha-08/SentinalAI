"""SentinelAI FastAPI Inference Server"""
import os, sys, time, logging, math, secrets
from pathlib import Path
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Dict, List
from collections import defaultdict, deque
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator
import httpx, asyncio
sys.path.insert(0, str(Path(__file__).parent.parent))
from inference.predictor import SentinelPredictor
from inference.deception import get_scorer, save_scorer
from inference.errors import ModelUnavailableError
from utils.features import FEATURE_NAMES
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("sentinel.api")

MODEL_DIR   = os.getenv("MODEL_DIR", str(Path(__file__).parent.parent/"models"))
BACKEND_API = os.getenv("SENTINEL_API", "http://localhost:5000/api")
API_KEY     = os.getenv("SENTINEL_KEY")
if not API_KEY:
    log.error("CRITICAL: SENTINEL_KEY environment variable is missing. Failing closed.")
    raise RuntimeError("Configuration error: SENTINEL_KEY environment variable is missing.")

THRESHOLD   = float(os.getenv("SCORE_THRESHOLD", "0.7"))

predictor = None
stats = {"total":0,"threats":0,"blocked":0,"start":datetime.now(timezone.utc).isoformat(),"scores":deque(maxlen=100),"times":deque(maxlen=100),"classes":defaultdict(int)}

@asynccontextmanager
async def lifespan(app: FastAPI):
    global predictor
    predictor = SentinelPredictor(model_dir=MODEL_DIR)
    log.info("Inference model state: " + ("ready" if predictor._loaded else "unavailable"))
    yield
    try:
        if save_scorer():
            log.info("Deception Q-table successfully flushed to disk on shutdown.")
        else:
            log.debug("Deception state was not initialized; no learning-state write.")
    except Exception as e:
        log.warning(f"Failed to flush Q-table on shutdown: {e}")

app = FastAPI(title="SentinelAI Inference Engine", version="2.1.0", lifespan=lifespan)

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
    timestamp: str = None
    class Config:
        extra = "allow"
        allow_inf_nan = False

    @model_validator(mode="before")
    @classmethod
    def finite_features(cls, values):
        if isinstance(values, dict):
            for name in FEATURE_NAMES:
                if name in values:
                    try:
                        finite = math.isfinite(float(values[name]))
                    except (TypeError, ValueError, OverflowError):
                        finite = False
                    if not finite:
                        raise ValueError(f"{name} must be a finite number")
        return values

class SessionData(BaseModel):
    sessionId: str = ""; sourceIP: str = "0.0.0.0"
    durationSeconds: float = Field(default=0.0, ge=0, allow_inf_nan=False); loginSucceeded: bool = False
    commands: List[Dict] = Field(default_factory=list, max_length=10000); iocCount: int = Field(default=0, ge=0); deceptionProfile: str = "ubuntu_22"

def _public_result(r: dict) -> dict:
    if not isinstance(r, dict):
        return r
    return {k: v for k, v in r.items() if k not in ("featureVector", "featureSchemaVersion")}

def _upd(r):
    stats["total"]+=1; stats["scores"].append(r["threatScore"]); stats["times"].append(r.get("inferenceTimeMs",0))
    stats["classes"][r["predictedClass"]]+=1
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
    return predictor.get_model_info()

@app.get("/model/stats", dependencies=[Depends(verify_api_key)])
async def model_stats():
    sc,it=list(stats["scores"]),list(stats["times"])
    return {"totalPredictions":stats["total"],"totalThreats":stats["threats"],"totalBlocked":stats["blocked"],"avgThreatScore":round(sum(sc)/len(sc),4) if sc else 0,"avgInferenceMs":round(sum(it)/len(it),2) if it else 0,"classCounts":dict(stats["classes"]),"uptimeStart":stats["start"]}

@app.post("/predict", dependencies=[Depends(verify_api_key)])
async def predict(record: Record, bg: BackgroundTasks, explain: bool = False):
    if not predictor: raise HTTPException(503,"Not ready")
    r = predictor.predict(record.model_dump(), explain=explain); _upd(r)
    bg.add_task(_notify, r, record.sourceIP)
    return {"success":True,"sourceIP":record.sourceIP,"result":_public_result(r),"timestamp":datetime.now(timezone.utc).isoformat()}

@app.post("/predict/internal", dependencies=[Depends(verify_api_key)])
async def predict_internal(record: Record, explain: bool = False):
    """Backend-owned persistence: returns the raw vector and never calls back."""
    if not predictor: raise HTTPException(503, "Not ready")
    result = predictor.predict(record.model_dump(), explain=explain)
    _upd(result)
    return {"success": True, "result": result}

@app.post("/predict/honeypot/internal", dependencies=[Depends(verify_api_key)])
async def predict_honeypot_internal(session: SessionData):
    if not predictor: raise HTTPException(503, "Not ready")
    result = predictor.predict_from_honeypot(session.model_dump())
    _upd(result)
    return {"success": True, "result": result}

@app.post("/predict/eval", dependencies=[Depends(verify_api_key)])
async def predict_eval(record: Record, explain: bool = False):
    """
    Isolated model evaluation endpoint for benchmark datasets (e.g. CICIDS2017).
    Executes full ML feature extraction, Random Forest classification, Isolation Forest
    anomaly detection, and ThreatScore calculation.
    GUARANTEE: Completely bypasses background notifications, database persistence,
    server-wide stats mutation, and automated containment.
    """
    if not predictor: raise HTTPException(503, "Not ready")
    r = predictor.predict(record.model_dump(), explain=explain)
    return {"success":True,"evaluation":True,"sourceIP":record.sourceIP,"result":_public_result(r),"timestamp":datetime.now(timezone.utc).isoformat()}


@app.post("/predict/batch", dependencies=[Depends(verify_api_key)])
async def predict_batch(records: List[Record], bg: BackgroundTasks):
    if not predictor: raise HTTPException(503,"Not ready")
    if len(records)>500: raise HTTPException(400,"Max 500")
    results=[]
    for rec in records:
        r=predictor.predict(rec.model_dump()); _upd(r); results.append({"sourceIP":rec.sourceIP,"result":_public_result(r)})
        if r["threatScore"]>=THRESHOLD: bg.add_task(_notify,r,rec.sourceIP)
    return {"success":True,"total":len(results),"threatCount":sum(1 for r in results if r["result"]["threatScore"]>=THRESHOLD),"results":results}

@app.post("/predict/honeypot", dependencies=[Depends(verify_api_key)])
async def predict_honeypot(s: SessionData, bg: BackgroundTasks):
    if not predictor: raise HTTPException(503,"Not ready")
    r=predictor.predict_from_honeypot(s.model_dump()); _upd(r)
    bg.add_task(_notify,r,s.sourceIP)
    return {"success":True,"sessionId":s.sessionId,"sourceIP":s.sourceIP,"result":_public_result(r),"timestamp":datetime.now(timezone.utc).isoformat()}

@app.post("/deception/score", dependencies=[Depends(verify_api_key)])
async def deception_score(s: SessionData):
    res = get_scorer().process_session(s.model_dump())
    return {"success": True, "result": res}

class AuthTelemetryRecord(BaseModel):
    event_type: str = "AUTH_FAILURE"
    src_ip: str = "0.0.0.0"
    dst_ip: str = None
    dst_port: int = 22
    service: str = "ssh"
    user_identity: str = None
    raw_message: str = None
    timestamp: float = None

@app.post("/predict/auth/shadow", dependencies=[Depends(verify_api_key)])
async def predict_auth_shadow(auth_record: AuthTelemetryRecord):
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
        return {"success": False, "error": str(exc)}

if __name__=="__main__":
    import uvicorn
    uvicorn.run("inference.main:app",host="0.0.0.0",port=8000,reload=True)
