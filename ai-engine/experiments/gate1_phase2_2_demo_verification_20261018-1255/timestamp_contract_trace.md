# SENTINELAI — END-TO-END TIMESTAMP CONTRACT TRACE

**Verification Timestamp:** 2026-10-18T12:55:00+05:30  
**Phase:** Phase 2.2 — Demonstration-Path Verification  
**Auditor:** Senior Security & ML Verification Engineer  
**Repository:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  

---

## 1. End-to-End Pipeline Architecture

The lifecycle of timestamp data across SentinelAI spans four distinct architectural layers:

```
[ Honeypot / Cowrie Event ]
           │
           ▼
[ Node.js Honeypot Session Collector ] (session_collector.js / HoneypotSession.js)
           │
           ▼
[ Node.js Honeypot Closure Analysis ] (honeypotService.js)
           │ HTTP POST /predict/honeypot or /predict/honeypot/internal
           ▼
[ FastAPI Inference Service ] (inference/main.py - SessionData validation)
           │
           ▼
[ Feature Extraction ] (utils/features.py - extract_features_from_honeypot -> compute_time_of_day)
           │ 53-dimensional float64 vector (Indices 51, 52)
           ▼
[ Model Inference ] (inference/predictor.py - rf_classifier_cicids_v2.pkl)
```

---

## 2. Forensic Trace & Answers to Contract Questions

### Question 1: Where `session.startTime` is originally assigned?
- **Finding:** `CONFIRMED`.
- **Source References:**
  - `honeypot/collectors/session_collector.js` (Line 10):
    ```javascript
    const s = await HoneypotSession.create({
      sessionId, sourceIP, sourcePort, honeypotNode, protocol, geoLocation,
      status: 'active',
      startTime: new Date()
    });
    ```
  - `backend/models/HoneypotSession.js` (Line 35):
    ```javascript
    startTime: { type: Date, default: Date.now },
    ```
- **Conclusion:** `session.startTime` is assigned when the Cowrie event collector handles the `SESSION_OPENED` event and persists the new session document in MongoDB.

### Question 2: Whether it represents event time or processing time?
- **Finding:** `CONFIRMED`.
- **Analysis:** In `onSessionOpened(data)`, `data.timestamp` from the honeypot daemon is ignored; `startTime: new Date()` is invoked on the backend server.
- **Conclusion:** It represents **processing / ingestion time**, NOT the sensor network capture event time.

### Question 3: Whether timezone-naive values have a documented timezone?
- **Finding:** `CONFIRMED`.
- **Analysis:**
  - In MongoDB / Mongoose, `Date` objects are stored in BSON UTC milliseconds without an explicit timezone string.
  - Prior to Phase 2.1, there was no documented contract for string timestamps passed into the Python engine.
  - In Phase 2.1, `ai-engine/utils/features.py` established an explicit UTC contract:
    ```python
    if parsed_dt.tzinfo is None:
        dt = parsed_dt.replace(tzinfo=datetime.timezone.utc)
    else:
        dt = parsed_dt.astimezone(datetime.timezone.utc)
    ```
  - Any naive timestamp reaching the Python engine is deterministically interpreted as UTC.

### Question 4: Whether JavaScript parsing can reinterpret a naive timestamp?
- **Finding:** `CONFIRMED`.
- **Analysis:**
  - In V8 / Node.js, `new Date("2026-10-18T12:00:00")` (ISO without `Z` or offset) is parsed according to host local machine time.
  - When `.toISOString()` is called in `honeypotService.js`, the local UTC offset is applied, producing a shifted UTC timestamp.
  - However, for authentic sessions created via `session_collector.js`, `session.startTime` is an instantiated `Date` object (`instanceof Date`), which `.toISOString()` serializes directly to UTC ISO-8601 with trailing `'Z'`.

### Question 5: Whether the timestamp fields accepted by `SessionData` are actually consumed downstream?
- **Finding:** `CONFIRMED`.
- **Trace Proof:**
  1. `ai-engine/inference/main.py`: `SessionData` accepts `startTime: str = None` and `timestamp: str = None`.
  2. `predict_honeypot_internal` passes `session.model_dump()` to `predictor.predict_from_honeypot(session)`.
  3. `predictor.py` line 371 calls `extract_features_from_honeypot(session)`.
  4. In `ai-engine/utils/features.py` line 365:
     ```python
     timestamp = session.get("startTime") or session.get("timestamp")
     ```
  5. In line 418, `"timestamp": timestamp` is forwarded to `extract_features_from_record()`.
  6. Line 295–296 calls `compute_time_of_day(ts_val)`.
- **Conclusion:** The fields are explicitly and directly consumed in feature calculation.

### Question 6: Whether missing timestamps consistently produce the intended `(0.0, 0.0)` pair?
- **Finding:** `CONFIRMED`.
- **Code Reference:** `ai-engine/utils/features.py` lines 162–163:
  ```python
  if timestamp_val is None:
      return 0.0, 0.0
  ```
- **Test Evidence:** Confirmed by `test_time_of_day_none_timestamp_deterministic_fallback` and smoke test Sample 1.

### Question 7: Whether malformed, non-finite, and out-of-range inputs fail safely?
- **Finding:** `CONFIRMED`.
- **Code Reference:** `ai-engine/utils/features.py` lines 167–229:
  - Non-finite numbers (`NaN`, `Inf`): `if not np.isfinite(val): return 0.0, 0.0`
  - Extreme out-of-range epoch floats: `if not (-62135596800.0 <= val <= 253402300799.0): return 0.0, 0.0`
  - Unparseable strings, empty strings, `"none"`, `"nan"`: Caught and return `0.0, 0.0`
  - Type errors (lists, dicts, unexpected objects): Fall through `else:` and return `0.0, 0.0`
  - Strict exception capture: `(ValueError, OverflowError, OSError, TypeError)`
- **Conclusion:** Zero crashes, zero unhandled exceptions.

### Question 8: Whether feature order and model dimensionality remain compatible?
- **Finding:** `CONFIRMED`.
- **Dimensionality:** Array length is exactly 53 (`dtype=np.float64`).
- **Index Alignment:**
  - Index 50: `payload_entropy`
  - Index 51: `time_of_day_sin`
  - Index 52: `time_of_day_cos`
- **Model Compatibility:** Matches `len(FEATURE_NAMES) == 53`. All production pipelines (`rf_classifier_cicids_v2.pkl`, `isolation_forest_cicids.pkl`) validate against 53 features during startup.
