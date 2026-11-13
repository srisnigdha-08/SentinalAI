# Honeypot-session ML (separate from network-flow ML)

| | Network-flow ML | Honeypot-session classification |
|---|---|---|
| Input | 53 flow features (CICFlowMeter style) | Cowrie session: commands, timing, logins |
| Model | XGBoost `xgb_cicids_v1` + Isolation Forest | **Rule-based** MITRE classifier (`honeypot_rules`) |
| ML candidate | protocol v4 (not promoted) | **none**: blocked by missing labels |

## What exists (`ai-engine/session_ml/pipeline.py`)

- **Features (`session_v1`):**
  - command count, unique-command ratio, distinct programs, bigram diversity
  - duration, login success, failed logins
  - inter-command gap mean, median and standard deviation
  - longest command, pipes and redirects
  - downloads, execution of downloaded files, fingerprinting commands, IOC count
  - per-intent counts
  - Commands are read as text and never executed.
- **Label provenance:**
  - `rule` labels come from the existing classifier: the baseline, never ground truth.
  - `manual` labels need a labeller.
  - `external` labels need a reference to their source.
- **Leakage-safe split:** train on earlier sessions, test on later ones. Every session from one source IP stays on
  the side of that IP's first session.
- **Readiness gate:** ≥ 30 independent labels in ≥ 2 classes, spanning ≥ 14 days.
- **Shadow harness:** logistic regression compared with the rule baseline on the same later sessions (per-class
  precision, recall and F1, macro F1, confusion matrix, per-feature contributions). It never writes a model and is
  never served.

## Why there is no classifier

On 2026-11-13 there were 27 closed sessions (19 in `sentinel-demo`, 8 in `sentinel-db`). All were labelled by the
rules and none were analyst-verified. A model trained on rule labels would only imitate the rules, and any score
would be circular. The gate refuses to train, and the dashboard reports this as **Blocked**.

To unblock it, label sessions independently (analyst review, or an external labelled corpus with its reference)
until the gate passes. Then run `train_and_evaluate` and compare with the rule baseline. Keep the rules until an
independent, time-split evaluation shows the candidate is better.
