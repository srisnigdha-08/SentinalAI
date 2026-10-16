# Supplemental verified findings — 2026-10-14

After baseline establishment, an additional in-process AI validation probe used
a mocked startup predictor and no database/network notifications. POST
/predict/eval with raw JSON `{"flow_duration":NaN}` returned **500**. Pydantic
correctly rejects non-finite values, but FastAPI's default validation response
tries to echo the non-finite input through strict JSON serialization. Expected:
sanitized 422 validation response, no inference/statistics/learning-state write.
This is NATIVE-10 (Medium), pre-existing; add non-finite, malformed and sensitive
input regressions and omit raw input/exception context from validation responses.

The same probe logged “Deception Q-table successfully flushed” although the
learner was uninitialized and save_scorer performed no write. This is NATIVE-11
(Low), pre-existing inaccurate operational evidence. Return an explicit write
result and log a flush only when it actually occurred; regression should verify
prediction-only shutdown never initializes or writes learning state.

No model thresholds, feature defaults, model artifacts or learning state were
changed by this probe. Missing feature fields retain their documented preprocessing
defaults; rejection of absent optional fields is not proposed. The original
baseline report/evidence remains unchanged.
# Additional integration findings

- **NATIVE-12 — Medium, pre-existing:** `backend/services/aiEngineService.js`
  swallowed Python 422 input errors into null, and `/api/ai/analyze` reported 503.
  Malformed client features therefore appeared to be infrastructure outages.
  Targeted contract tests now require sanitized 422 propagation; real-service
  acceptance separately verifies that invalid requests create no predictions.
- **NATIVE-13 — Medium, pre-existing:** the backend readiness probe used only the
  unauthenticated Python `/ready` endpoint. Loaded models could conceal an incorrect
  internal service key. Readiness now also authenticates `/model/info`; tests cover
  valid credentials, incorrect credentials, unavailable models and sanitized errors.

- **NATIVE-14 — Medium, measured model-validation limitation:** archived DDoS row
  18884 naturally returned ThreatScore 0.6999 and ALLOW under the preserved 0.7
  MONITOR threshold. This is evidence of a borderline sample, not a justified
  reason to silently alter thresholds or an estimate of general model accuracy.
  A representative independent evaluation and separately reviewed decision policy
  remain necessary before production claims.
- **NATIVE-15 — High, pre-existing confidentiality finding:** honeypot list/detail
  endpoints allowed viewer access and serialized captured usernames/passwords.
  Response filtering now preserves attempt/success metadata while excluding those
  fields for viewers or an unknown role; original records and analyst/admin access
  remain unchanged. Five mocked controller regressions verify this boundary.
  Existing public registration may assign analyst; trusted operator enrollment is
  a separate unresolved production policy. It was preserved under the approved
  authentication contract rather than silently changed.
