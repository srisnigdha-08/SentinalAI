# SentinelAI project metrics and research findings

Every figure below comes from a recorded run; the source is given with each table. Nothing here was re-run for this
document, no model was retrained, and the four protected CSE-CIC-IDS2018 test days were never read.

## 1. Dataset: CICIDS2017 (source: `audit/ML_EVAL_PLAN.md` §2)

Flows per file with the project's label map, before any cap:

| Day / file | BENIGN | Attack flows (project class, original tool) |
|---|---|---|
| Monday | 529,918 | none |
| Tuesday | 432,074 | 7,938 Credential Stuffing (FTP-Patator), 5,897 SSH Brute Force |
| Wednesday | 440,031 | 252,661 DDoS (DoS Hulk, GoldenEye, slowloris, Slowhttptest), 11 RCE (Heartbleed) |
| Thursday AM (web attacks) | 168,186 | 1,507 Credential Stuffing (web brute force), 652 XSS, 21 SQL Injection |
| Thursday PM (infiltration) | 288,566 | 36 Lateral Movement |
| Friday AM | 189,067 | 1,966 Malware Beacon (Bot) |
| Friday PM (port scan) | 127,537 | 158,930 Port Scan |
| Friday PM (DDoS) | 97,718 | 128,027 DDoS (LOIC) |

- 7 of the 10 trained classes occur on exactly one day; only DDoS and Credential Stuffing span two days, each with a
  different tool on each day.
- "Data Exfiltration" has no samples (the model never saw it).

## 2. Training and test split of the served model (source: `audit/ML_EVAL_PLAN.md` §1, §5)

| Stage | Rows |
|---|---|
| After per-class caps | 148,015 |
| After exact-duplicate removal | 124,534 (23,481 removed; 33 vectors with conflicting labels kept) |
| Train / test (stratified random 80/20, seed 42) | 99,627 / 24,907 |
| Test: attack / benign | 6,236 / 18,671 |

Caps and de-duplication shrink some classes sharply (Port Scan 158,930 → 354 after de-duplication: 71 test rows), so
small-class figures rest on very few flows.

## 3. Served model `xgb_cicids_v1` on its random test split (P5, 2026-11-02, inference only)

Accuracy **0.9897**, macro F1 **0.8738**, weighted F1 0.9907, macro precision 0.8944, macro recall 0.8848,
PR-AUC (attack vs benign) 0.9995.

| Class | Precision | Recall | F1 | Test support |
|---|---|---|---|---|
| BENIGN | 0.9994 | 0.9964 | 0.9979 | 18,671 |
| SSH Brute Force | 0.9984 | 1.0000 | 0.9992 | 644 |
| SQL Injection | 1.0000 | 0.5000 | 0.6667 | **4** |
| Port Scan | 0.8500 | 0.9577 | 0.9007 | 71 |
| DDoS | 0.9967 | 0.9994 | 0.9981 | 3,610 |
| RCE Attempt | 1.0000 | 1.0000 | 1.0000 | **2** |
| XSS Attempt | 0.4071 | 0.7923 | 0.5379 | 130 |
| Malware Beacon | 0.8824 | 0.9896 | 0.9329 | 288 |
| Credential Stuffing | 0.9772 | 0.8980 | 0.9359 | 1,480 |
| Lateral Movement | 0.8333 | 0.7143 | 0.7692 | **7** |

Rows in bold have too few test flows for a meaningful estimate.

## 4. Detection thresholds and false positives

| Decision rule | Attack recall | Benign false-positive rate (95 % CI) | Source |
|---|---|---|---|
| Classifier says "not BENIGN" | 99.81 % | 0.359 % (0.28–0.46) | P5 |
| **Alert line**: threat score ≥ 0.90 → ThreatLog + alert | 95.22 % | 0.230 % (0.17–0.31) | P5 |
| **Block line**: score ≥ 0.92 → CRITICAL; auto-block if enabled | 94.76 % | 0.225 % (0.17–0.30) | P5 |
| Alert line on later, held-out traffic (chronological split) | 78.6 % | 0.154 % (0.136–0.174) | `README.md`, `docs/CRITICAL_FIXES_REPORT.md` |

The 0.90 line was chosen as the lowest line meeting a 0.1 % benign-alert target on a chronological validation split.
On the random test split its benign rate (0.23 %) is **above** that 0.10 % target: the target was not met there.

## 5. Generalisation to unseen days and tools (P3/P4, 2026-11-02, approved evaluation fits, nothing promoted)

| Protocol | Train / test rows | Attack recall (classifier) | Benign FPR | Attack recall at the 0.90 line |
|---|---|---|---|---|
| Random split (served model, P5) | 99,627 / 24,907 | **99.81 %** | 0.359 % | 95.22 % |
| Train Mon–Wed → test Thu + Fri (P3) | 52,916 / 71,618 | **50.6 %** (49.8–51.5) | 0.118 % | 12.1 % |
| Leave Tuesday out | 103,496 / 21,038 | 3.1 % | 0.379 % | 0.6 % |
| Leave Wednesday out | 104,678 / 19,856 | 33.4 % | 0.237 % | 1.7 % |
| Leave Thursday out | 100,430 / 24,104 | 17.3 % | **4.12 %** | 0.2 % |
| Leave Friday out | 77,020 / 47,514 | 23.4 % | **2.71 %** | 10.4 % |
| Leave Monday out (benign only) | 112,512 / 12,022 | – | 0.233 % | – |

Cross-tool example: trained on Wednesday's DoS tools, the model flagged 54.2 % of Friday's LOIC DDoS as attacks
(P3); a LOIC-trained model detected 0 % of the DoS tools.

**Cross-dataset (CSE-CIC-IDS2018 development days, `audit/ML_DEV_RESULTS.md`).** Pre-registered candidates trained
on both datasets did not meet the false-positive limits (e.g. 2018 benign FPR 2.85–3.16 % mean against a 0.47 %
limit). Held to a 0.1 % false-alarm line, recall on unseen 2018 days was about 7–13 % for the best candidate and 4–6 %
for the served recipe. No candidate was deployed. Four 2018 days remain untouched for an external test that has not
been run.

### Why high random-split accuracy does not show generalisation

1. **Leakage by construction.** A random split puts flows from the same attack burst (same tool, same hosts, same
   minutes) into both training and test sets; the test then measures recognition of near-copies.
2. **One tool per class.** Most classes were recorded with one tool on one day. The model learns that tool's
   fingerprint (window sizes, packet lengths), not the attack concept. The rehearsal's DDoS explanation was led by the
   TCP window size (`init_win_bytes_backward`, +3.66 log-odds).
3. **The day-held-out results are the honest estimate** of what happens on traffic the model has not seen: 3–51 %
   recall, and benign false alarms rising to 2.7–4.1 % on some days.
4. **Testbed artefacts.** Removing the testbed-specific features raised cross-dataset recall a little but multiplied
   false alarms 2–10× (`audit/ML_DEV_RESULTS.md`), so there was no easy fix.

### Negative results recorded as findings

- The served model does not generalise across capture days or tools (ML-007).
- Two-stage and reduced-feature candidates did not meet pre-registered false-positive limits; none was promoted.
- The anomaly detector catches some unseen attacks only as "Unknown" (review queue), never as alerts; on the
  Wednesday hold-out 3,747 attacks were scored anomalous but only 209 reached review alongside 55 benign flows.
- The alert line's benign rate on the random split (0.23 %) is above the 0.10 % target.

## 6. Inference latency (source: `docs/PERFORMANCE_AND_RESILIENCE.md`, `scripts/perf/engine_latency.py`)

| Measurement | Result |
|---|---|
| Single flow, idle machine, before PERF-001 (2026-11-02) | p95 35 ms; with SHAP p95 47 ms |
| Single flow, sequential, after PERF-001 | p50 15.8 ms, p95 30.3 ms; with SHAP p95 34.8 ms; explain p95 40.3 ms |
| Per-threat explanation `/explain/vector` | p50 26 ms, p95 48 ms; end to end through the backend 90 ms |
| Replay through the backend, rehearsal 2026-11-03 | 3–10 ms per flow as reported by the replay (first, cold call 143 ms) |
| Engine start-up (models verified, golden set reproduced) | 4.6–6.1 s; about 250–270 MB resident |
| In-process model call, one row | 5.0 ms with all cores → 2.8 ms single-threaded |

## 7. Load and throughput (source: `docs/PERFORMANCE_AND_RESILIENCE.md`)

| Test | 1 client | 5 clients | 10 clients | 20 clients | Errors |
|---|---|---|---|---|---|
| Engine `/predict/internal`, req/s (quiet run, after PERF-001) | 48 | 127 | 118 | 132 | 0 |
| Engine, req/s (busy machine, 2 runs) | 40 | 86–105 | 90–110 | 70–86 | 0 |
| Engine CPU, % of machine (old → new) | ≈ 60 → ≈ 3 | 51–61 → 7 | 60 → 7 | 58–60 → 8 | – |
| Backend end to end `/api/ai/analyze`, req/s | 35–47 | 66–98 | 74–94 | 76–98 | 0 |
| Backend p95 latency, ms | 36–50 | 89–107 | 151–196 | 269–364 | – |

Consistency under load: 360/360 predictions stored, 121/121 threats created with no duplicates, every role socket
received all 121 events, viewers only redacted IPs. Database: list query 3.9 → 12 ms and dashboard analytics 7 → 112 ms
from 1,000 to 50,000 threats (linear growth). Throughput gain from PERF-001 is load-dependent; the CPU reduction
reproduced in every run.

## 8. Testing and validation (2026-11-03)

| Suite | Result |
|---|---|
| Backend Jest | 1,178 passed, 13 skipped (batch 15, includes the CONT-001 regression tests) |
| AI engine pytest | 653 passed |
| Frontend unit tests | 70 passed |
| Playwright E2E (Chromium, Firefox, WebKit + device projects) | 240 passed, 0 failed (batch 14); batch 15: 235 passed, 5 failed from transient DNS and memory pressure, all 5 passing on re-run |
| Cross-service integration with live Cowrie (Demos A–C, auth, outage) | 42 passed, 0 failed |
| Load and failure-recovery harness | 15/15 |
| Clean-clone installation (throwaway MongoDB 7) | every step passed |
| Demo A/B/C rehearsal | all steps passed; one defect found and fixed (CONT-001) |
| Model registry and golden set | OK; model and Q-table hashes unchanged throughout batches 13–15 |
| GitHub Actions (7 jobs) | green on `f806459` |
