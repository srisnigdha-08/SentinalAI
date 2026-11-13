"""
Honeypot-SESSION machine learning (docs/SESSION_ML.md). Separate from the network-FLOW model (xgb_cicids_v1).

Status: pipeline only. Session features, labels with provenance, a leakage-safe split and a readiness gate exist.
No session classifier is trained or served: the project has no independently labelled sessions (all current
labels come from the rule-based MITRE classifier, which a model trained on them would merely imitate).
Sessions continue to be classified by the rules (utils.features.classify_honeypot_session).
"""
