"""
Honeypot-SESSION machine learning (docs/SESSION_ML.md). Separate from the network-FLOW model (xgb_cicids_v1): its own
feature schema (session_ml.features, "session_v2"), its own artifact directory and manifest (session_ml.classifier),
and no shared code path with the CICIDS predictor.

Status: infrastructure verified, model absent. Feature extraction, safe JSON-artifact loading, shadow inference on
/predict/honeypot/internal (as a separate "sessionML" block) and a gated, time-aware training/evaluation export exist.
No classifier is trained or shipped: the 2026-11-13 data audit found no independently labelled sessions (every label
comes from the rule-based classifier, which a model trained on it would merely imitate). Sessions continue to be
classified by the rules (utils.features.classify_honeypot_session); the shadow block never changes that result.
"""
