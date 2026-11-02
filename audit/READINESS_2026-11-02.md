# SentinelAI readiness report (2026-11-02, batch 10)

Supersedes `READINESS_2026-11-01.md` for demo readiness. "Verified" means run on this machine today: Windows 11,
local MongoDB 7, WSL Ubuntu with Cowrie. Anything not run is marked as such.

## 1. Features implemented (verified)

- **Cowrie honeypot pipeline:** real SSH sessions → parser → ingest → session analysis. The analysis covers
  rule-based classification, MITRE ATT&CK mapping, threat and deception scores, campaigns and canary alerts.
- **Adaptive deception:** a tabular Q-learning recommender with persisted decisions (`DeceptionDecision`). The
  rotator applies or keeps a decision, restarts Cowrie and records it, and the Q-table persists.
- **Detection:** served XGBoost + Isolation Forest (`xgb_cicids_v1`). Hashes and the golden set are verified at
  load; there is a REVIEW tier for anomalies the classifier calls benign; a degraded mode when the engine is down.
- **Explanations:** SHAP explanations at the engine API, plus a global SHAP summary in the dashboard.
- **Containment:** policy-governed and simulated. Protected targets, thresholds, auto-block (off by default), the
  mock adapter, deny-list, TTL reconciliation, rollback, audit trail and socket events.
- **Accounts and security:**
  - sessions with refresh rotation, `authVersion` and inactivity timeout;
  - RBAC (viewer, analyst, admin);
  - CSRF protection;
  - self-service password change;
  - CSP;
  - secret scanning in CI.
- **Testing:** integration harness (live Cowrie and least-privilege MongoDB variants), Playwright E2E on three
  browsers, and the ML evaluation pipeline with protected external data.

## 2. Issues fixed in this batch

| ID | Fix | Test |
|---|---|---|
| UI-002 | Adaptive Deception panel described per-request epsilon-greedy draws. It now names the persisted decision and states that a refresh reuses it. | `frontend/tests/modelHealth.test.mjs`; affected E2E specs 42/42 |
| TEST-006 | The below-block-line branch with auto-block on was never exercised. | `containmentPolicy` TEST 5b |
| XAI-001 (docs) | README claimed per-incident SHAP; corrected in two places, and in the runbooks. | — |
| Docs | Verified runbook `docs/DEMO_ABC_RUNBOOK.md`; stale reality-matrix rows updated (scorer, rotator, SHAP, sockets). | — |
| Perf | `scripts/perf/engine_latency.py` (idle-machine latency, SHAP content, memory) | ran twice, consistent |

## 3. Test results (exact counts, 2026-11-02)

| Suite | Result |
|---|---|
| Backend Jest | 1,148 passed, 13 skipped, 0 failed (73 suites + 4 skipped); containment suite after the new test 25/25 |
| Backend ESLint | clean |
| AI engine pytest | 636 passed, 0 failed |
| Frontend unit (`node --test`) | 53 passed, 0 failed |
| Frontend production build | OK |
| Frontend ESLint | **not configured** (no `eslint.config.*`); not run |
| Playwright, Chromium + Firefox + WebKit | 167 passed, **1 failed** (E2E-002, Firefox, intermittent; 40/40 repeated alone) |
| Integration, live Cowrie | **41 passed, 0 failed** |
| Integration, MongoDB `--auth` (`sentinel_app`) | **35 passed, 0 failed** |
| Registry integrity | 3/3 hashed artifacts match; `models/`, `runtime/` unchanged |
| Not run | Docker Compose (Docker not installed), nginx/TLS, real Windows Firewall adapter, mobile/tablet Playwright projects |

## 4. Performance (idle machine unless stated)

- **Single-flow inference** (HTTP, one client, golden vectors, 300 requests): p50 11 ms, p95 35 ms, p99 36 ms.
- **With SHAP:** p50 25 ms, p95 47 ms. Both are inside the 50 ms target.
- **Engine:** ready in 4.6–6.1 s; 272 MB resident; `/health` p50 15 ms.
- **End to end** (from the integration run, so the machine was shared with the harness):
  - 30 replayed flows → engine → MongoDB → sockets in 2.7 s, including process start and login;
  - socket recovery about 5 s across a backend restart;
  - no duplicate events (15 `new_threat` for 15 threats; 30 `ai_prediction` for 30 predictions).
- **Not measured:** dashboard first paint in a browser and concurrent load. The largest frontend chunk is the
  charting bundle, 386 kB (106 kB gzip).
- Earlier latency numbers from the ML dev batches (36–89 µs/row in batch) were taken under heavy contention and are
  not comparable.

## 5. AI/ML performance and limitations

- **Random split:** the served model scores 98.97 % accuracy and 0.874 macro F1 on a de-duplicated random split.
  Attack recall is 99.8 %, or 95.2 % at the 0.90 alert line.
- **Cross-day:** attack recall is 50.6 % on the time-forward split and 3–33 % leaving one day out. **It does not
  generalise to unseen days or tools.**
- **Cross-dataset development** (CSE-CIC-IDS2018): one candidate was eligible on development data. Its advantage
  disappears at a 0.1 % false-alarm line, so the external test is **DEFERRED** (`audit/EXTERNAL_TEST_DECISION.md`).
  Nothing was promoted.
- **Other limits:**
  - rare classes (SQL injection, remote code execution, lateral movement) have too little data to measure;
  - Data Exfiltration has no data at all;
  - per-flow SHAP is not attached to threats.

## 6. Demo readiness

| Demo | Status | Evidence | Caveats |
|---|---|---|---|
| **A — Honeypot Intelligence** | **READY** | Recorded Cowrie session → 12 MITRE techniques, threat score 0.99, deception score 49. Live SSH session (one command) → stored with its persona and 3 techniques. Persisted decision `APPLIED` (`ubuntu_22 → debian_11`); the next session saw `debian-prod-01` and was credited to it; Q-table persisted. | Rule-based classification, not ML. Persona effectiveness not measured. The rotator restarts Cowrie (drops open sessions; it waits unless `--force`). |
| **B — AI Threat Detection** | **READY** | Replay → AIPrediction ×30 → ThreatLog ×15 → socket events and alerts. Engine verified at load. Latency within target. | Recorded-flow replay, not live capture. Global SHAP only in the UI. Accuracy is in-distribution. |
| **C — Autonomous Incident Response** | **READY (simulated enforcement)** | Protected target refused; block → mock `ACTIVE` + deny-list + audit + event; idempotent repeat; TTL reconciliation; auto-block; operator rollback; outage → `DEGRADED`. Below-block-line branch unit-tested. | **No host-firewall rule is created** (mock adapter); the honeypot deny-list is the only real enforcement. |

## 7. Remaining technical issues

| Issue | Severity | Note |
|---|---|---|
| SEC-001 leaked passwords (9 records, public history) | High in any exposed setting | **OPEN, risk accepted by the owner** for local demos (`SEC001_REMEDIATION.md`) |
| XAI-001 per-flow SHAP not stored or shown per threat | Medium (feature gap) | engine supports it; needs a pipeline change |
| E2E-002 Firefox triage note, intermittent | Low (test) | about 2 in 380 runs; not reproduced in isolation |
| RL-001 remainder | Low | sessions still store their own closure-time recommendation (`recommendedProfile`), which can differ from the applied decision; not shown in the UI. No minimum-evidence rule; engine RNG unseeded. |
| Frontend has no lint configuration | Low | CI lints the backend only |
| Docker/nginx/TLS deployment, real firewall adapter | — | never executed; not claimed |

## 8. Setup requirements

- Windows 11 with Node 20+, and Python 3.12 in `ai-engine/.venv`.
- MongoDB 7 as a Windows service.
- WSL Ubuntu with Cowrie in `~/sentinelai-cowrie-test/cowrie`.
- `backend/.env`.
- The CICIDS2017 CSVs in `ai-engine/datasets/cicids2017/` (for replay).
- No Docker.

## 9. Demonstration commands

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\start-demo.ps1
```

```bash
bash scripts/demo/cowrie-demo-mode.sh on          # WSL
```

```powershell
. $env:USERPROFILE\.sentinelai\demo\demo-env.ps1
```

Then follow `docs/DEMO_ABC_RUNBOOK.md` §2–§4. Pre-viva self-check: `node scripts/integration/run_integration.cjs --cowrie`
(expect 41/41). Stop with `scripts\demo\stop-demo.ps1` and `bash scripts/demo/cowrie-demo-mode.sh off`.

## 10. Suggested viva explanation (about 90 seconds)

"SentinelAI connects three things. First, a real Cowrie SSH honeypot. Its sessions are parsed, mapped to MITRE
techniques and scored. A small Q-learning recommender picks the next decoy persona, which a rotator applies; the
decision is persisted, so what we apply is exactly what was decided. Whether that improves engagement I have not
measured.

Second, an XGBoost and Isolation Forest engine scoring recorded CICIDS2017 flows. It reaches 98.97 % on a random
split, but I tested it honestly on unseen days and tools and it does not generalise: recall falls to single digits.
Even a pre-registered cross-dataset candidate lost its advantage at a realistic false-alarm rate, so I kept the
served model and deferred the one-shot external test.

Third, policy-governed containment with protected targets, thresholds, audit and rollback. Enforcement is simulated
by a mock adapter, and only the honeypot itself refuses blocked IPs.

Everything I claim has a test or a recorded run behind it: 41 live integration checks, three browsers, about 1,800
unit tests."

## 11. Git changes and commit plan (not committed; awaiting approval)

Working tree: the files below, plus `.claude/` and local run logs (excluded).

1. `fix(frontend): describe the persisted deception decision on Honeypot Analytics (UI-002)`:
   `frontend/src/utils/modelHealth.js`, `frontend/src/pages/HoneypotAnalytics.jsx`, `frontend/tests/modelHealth.test.mjs`
2. `test(backend): cover auto-block on with a score between the alert and block lines (TEST-006)`:
   `backend/tests/containmentPolicy.test.js`
3. `feat(perf): single-flow engine latency probe`: `scripts/perf/engine_latency.py`
4. `docs: verified Demo A/B/C runbook, SHAP claims corrected, readiness report (batch 10)`:
   `docs/DEMO_ABC_RUNBOOK.md`, `docs/THREAT_DEMO_RUNBOOK.md`, `README.md`, `audit/FINDINGS.md`, `audit/FIXES.md`,
   `audit/LEDGER.md`, `audit/READINESS_2026-11-02.md`

Not committed: `.claude/` (including the local `launch.json` entries added for this session), run logs under
`ai-engine/experiments/*_stdout.txt`, `scripts/integration/runs/` (git-ignored), Playwright reports.
