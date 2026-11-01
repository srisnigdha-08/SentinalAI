# Findings Register (working copy — updated per stage)

Labels: CONFIRMED / LIKELY / POSSIBLE / UNKNOWN. Source: static / ran / prior-report / docs.
No secret values appear in this file.

---

## Stage 1 findings

```
ID: SEC-001 | Priority: P1 | Label: CONFIRMED (ran: git show + value comparison, match flag only)
Where: Git history, commit 315700c (2026-10-18), file scratch/run_browser_script.mjs:12-15 (removed in a7fa029)
       also scratch/regenerate_audit_and_fixtures.mjs:97,160 (same commit range)
What: The honeypot ingest API key that is CURRENTLY in use (identical to HONEYPOT_API_KEY in backend/.env and
      deployment/.env.demo) is committed in Git history, together with three verification-account passwords.
      Deleting the file in a7fa029 did not remove it from history.
Why it matters: Anyone with a clone of db-fixes can POST forged honeypot events to /api/honeypot/ingest*,
      which create sessions/alerts and (per trigger_block.js) can drive auto-containment decisions against an
      IP of their choosing. History is on branch db-fixes only; not in origin/main per local refs.
Fix: Rotate HONEYPOT_API_KEY (and the verify-account passwords) now. Before pushing db-fixes, either rewrite
     history (git filter-repo) or accept the leak because the key is rotated. Rotation is the actual fix.
Proof of fix: `git grep -F "<new key>" $(git rev-list --all)` returns nothing; old key rejected by ingest (401).
```

```
ID: OPS-001 | Priority: P1 | Label: CONFIRMED (static)
Where: backend/utils/seed.js:3-9,79-83 (`npm run seed`); backend/utils/clean.js:3-22 (`npm run clean`)
What: `npm run seed` deletes ALL documents in User, ThreatLog, HoneypotSession, Alert, AIPrediction, BlockedIP,
      Campaign on MONGO_URI (default sentinel-db) with no prompt; its only guard is NODE_ENV=production, and
      backend/.env sets NODE_ENV=development. `npm run clean` wipes all telemetry with no guard at all.
Why it matters: One mistyped npm script before the viva destroys the real demo database and all user accounts.
      seed.js also fills the DB with 150 synthetic threats — relevant to "live data" claims (Stage 3).
Fix: Require an explicit `--confirm <dbName>` argument matching the target DB name, refuse any DB not ending
     in `_demo`/`_test` unless `--force`, and print counts before deleting.
Proof of fix: Running `npm run seed` against sentinel-db without the flag exits non-zero and counts are unchanged.
```

```
ID: TEST-001 | Priority: P1 | Label: LIKELY (static)
Where: frontend/playwright.config.js webServer[0].reuseExistingServer = !process.env.CI (untracked file);
       scripts/start-test-backend.cjs:17-21 (the only DB-name guard for the server)
What: Locally, if a normal dev backend is already listening on :5000 (connected to sentinel-db), Playwright reuses
      it. The "test DB" guard lives in start-test-backend.cjs, which then never runs; global-setup seeds
      sentinelai_test while the specs (user-management, password-change, settings) mutate the REAL backend/DB.
Why it matters: Running `npm run test:e2e` while the demo stack is up can change passwords / users in sentinel-db.
      Also the seeded logins won't exist there, so tests fail confusingly.
Fix: Set reuseExistingServer: false for the backend, or add a /health check in global-setup that asserts the
     running server reports a DB name containing "test".
Proof of fix: Start the dev backend, run playwright → it refuses to start (port busy) or global-setup aborts.
```

```
ID: TEST-002 | Priority: P2 | Label: LIKELY (static)
Where: .github/workflows/e2e.yml env block; backend/config/validateEnv.js:63-80; .gitignore (now ignores .env.test)
What: The new E2E workflow does not set HONEYPOT_API_KEY or SENTINEL_KEY, and backend/.env.test is now
      git-ignored, so in CI validateEnv() throws and the backend webServer never starts.
Why it matters: The E2E suite would never actually run in CI; "E2E tested in CI" would be a false claim.
Fix: Add both keys (test values ≥8 chars) to the workflow env.
Proof of fix: Workflow run shows backend started and specs executed.
```

```
ID: ML-001 | Priority: P1 (provisional; finalised in Stage 5) | Label: CONFIRMED (static + ran python meta read)
Where: ai-engine/utils/features.py:26 (FEATURE_NAMES incl. time_of_day_sin/cos), :31 FEATURE_SCHEMA_VERSION v2.1_53feat;
       every classifier *_meta.json in ai-engine/models/ and models/ lists both time-of-day features
What: All saved classifiers — including the runtime one (ai-engine/models/rf_classifier_cicids_v2.pkl, trained
      2026-08-09) — were trained with time-of-day features. Whatever the "leakage fix" was, no saved artefact
      was trained without these features.
Why it matters: The README/paper metrics (98.43% / 0.9862 / 99.13%) come from these models; if time-of-day leaks
      the label in CICIDS2017 (attacks scheduled on specific days/hours), the metrics are inflated.
Fix: Determined in Stage 5.
Proof of fix: Retrained model meta without the features + re-reported metrics.
```

```
ID: ML-002 | Priority: P2 | Label: CONFIRMED (static + ran sha256)
Where: models/rf_classifier_cicids_v2.pkl (40.8 MB, trained 2026-08-14, acc 0.9863/F1w 0.9878) vs
       ai-engine/models/rf_classifier_cicids_v2.pkl (46.2 MB, trained 2026-08-09, acc 0.9843/F1w 0.9862);
       ai-engine/inference/main.py:23,38; predictor.py:116-140; ai-engine/.env MODEL_DIR=./models
What: The two RF files are different models. Runtime loads `$MODEL_DIR/rf_classifier_cicids_v2.pkl` where
      MODEL_DIR is relative to the process CWD. Started as the README says (from ai-engine/), it loads the
      ai-engine copy — whose metrics match the README. The root copy is a later retrain referenced by no code
      (train.py --model-dir defaults to "models" relative to CWD, so it was probably produced by running
      training from the repo root). isolation_forest_cicids.pkl is byte-identical in both places.
Why it matters: Which model is "the" model depends on the working directory; the newer model is silently unused.
Fix: Delete or archive root models/ (after you decide which is canonical); make MODEL_DIR default absolute.
Proof of fix: /model/info reports the expected version/trained_at regardless of CWD.
```

```
ID: DOC-001 | Priority: P2 | Label: CONFIRMED (static)
Where: README.md:213-217; ai-engine/inference/main.py:1-28 (no load_dotenv anywhere in ai-engine/inference)
What: README says `cp .env.example .env` then `uvicorn inference.main:app --host 0.0.0.0 ...`. Nothing loads that
      .env, so SENTINEL_KEY is unset and main.py raises RuntimeError at import. The README also tells you to bind
      0.0.0.0, contradicting the code's loopback default (main.py:270).
Why it matters: Following the README literally, the AI engine does not start; if fixed by exporting vars, it is
      exposed on all interfaces (it is key-protected, but /docs and /health are not).
Fix: README: `uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file .env`.
Proof of fix: Fresh shell, follow README → /health returns 200.
```

```
ID: CFG-001 | Priority: P3 | Label: CONFIRMED (static, values not printed)
Where: deployment/.env.production (untracked, local); backend/config/validateEnv.js:86-89
What: The local production profile still contains CHANGE_ME placeholders for all secrets and the admin password.
      validateEnv() would refuse to boot on the secrets (good), but ADMIN_INITIAL_PASSWORD is only length-checked,
      never placeholder-checked. deployment/.env points at host `mongo` (Docker) though Docker files were removed.
Fix: Add placeholder check for ADMIN_INITIAL_PASSWORD; delete stale deployment/.env or mark it.
```

```
ID: HYG-001 | Priority: P3 | Label: CONFIRMED (static)
Where: 21 files in ai-engine/models (≈220 MB of .pkl incl. .bak), 5 .pkl + 6 .parquet in ai-engine/experiments,
       root models/; 15 *.bak-*/ *.orig-* source files tracked under backend/ (e.g. server.js.bak-phase6-20261015)
What: Superseded model files and backup copies of source sit next to live code.
Why it matters: Examiners/readers can't tell which file is live; grep results mislead; repo is heavy.
Fix: Move to an archive branch or a release asset; keep one canonical model + meta.
```

```
ID: CI-001 | Priority: P3 | Label: CONFIRMED (static)
Where: .github/workflows/ci.yml frontend job (only `npm run build`)
What: Frontend unit tests (`node --test tests/*.test.mjs`, 7 files) are never run in CI.
Fix: Add `npm test` step.
```

---

## Stage 2 findings

```
ID: CORE-001 | Priority: P1 | Label: CONFIRMED (static)
Where: backend/services/containmentService.js:501-599 (blockThreat), :605-700 (blockIPManual), :783-852 (executeAutoBlock);
       callers aiService.js:105-117, honeypotService.js:217-233, threatService.js:126-135, threatController.js:431
What: "Blocking" via auto-block, the per-threat Block button and manual block-ip never calls any containment adapter.
      It writes a BlockedIP row, sets ThreatLog status BLOCKED with autonomousAction.taken=true, emits ip_blocked and
      creates an "IP Address Blocked (Auto)" alert. The only reader of BlockedIP is the Cowrie blocker plugin, which
      refuses SSH connections to the honeypot itself.
      Only the policy path (POST /api/containment/actions) calls an adapter — MockContainmentAdapter by default, and
      its success is recorded as ACTIVE.
Symptoms:
  - Dashboard.jsx:237 toast "IP <x> blocked successfully" (DB-only path)
  - useRealTimeAlerts.js:59 toast "🚫 IP Blocked" on every ip_blocked event (DB-only path)
  - ThreatLogs.jsx:117 "Containment rule active for <x>" / Settings.jsx:94 "containment policy applied" (mock adapter)
  - Legacy path skips containmentPolicyService entirely; BlockedIP has no TTL; no protected-range check
  - Even the policy path protects only loopback/link-local/multicast/broadcast (containmentPolicyService.js:11-24);
    RFC1918 ranges, the gateway and the backend host are not protected
Why it matters: "Automated containment" is not true in any default configuration, and the UI says an IP is blocked
      when nothing on the network changed. "Show me the firewall rule" in a viva exposes it.
Fix (cheapest honest): (1) UI states driven by ContainmentAction.enforcementBackend: "Recorded (honeypot deny-list)"
      vs "Firewall rule applied (mock | windows-firewall)". (2) Route executeAutoBlock/blockThreat through
      requestContainment so every block goes policy → adapter → ContainmentAction. (3) Add RFC1918 + allowlist.
Proof of fix: With mock adapter, POST /threats/:id/block response/toast says "simulated"; adapter spy shows auto-block
      calls applyRule once; policy rejects 10.0.0.5 unless allowlisted.
```

```
ID: CORE-002 | Priority: P1 | Label: CONFIRMED (static)
Where: ai-engine/utils/features.py:318-400 (extract_features_from_honeypot); ai-engine/inference/predictor.py:369-420
What: Honeypot sessions are not classified by ML on observed data. A hand-written rule picks a class from login
      success, command keywords, IoC count and duration; the code then builds a 53-feature "network flow" from
      hard-coded per-class means (PROFILES_MEANS) and feeds that synthetic vector to RF/IF, which largely reproduces
      the rule's choice. Score = 0.7·RF + 0.3·IF + 0.02 × command_count (capped 0.99).
Why it matters: Saying the RF "classifies honeypot sessions" is misleading — it scores fabricated inputs. The
      +0.02/command term means ~35 commands of anything cross the 0.92 block threshold (backend/trigger_block.js
      does exactly this).
Fix: Reword ("rule-based session categorisation; RF applies to network flows") or train a session-level model on
     real Cowrie features. Remove or justify the per-command term.
Proof of fix: Test documenting that honeypot class == rule label, or a new model with its own evaluation.
```

```
ID: CORE-003 | Priority: P1 | Label: CONFIRMED (static)
Where: backend/routes/aiEngine.js:123 (only in-app inference caller); ai-engine/demo/replay_cicids.py:299 (/predict/eval);
       honeypot/sniffer/sniffer.py:103-160 (labels PCAP → CSV, never calls /predict)
What: Nothing feeds live network traffic to the detector. Detection runs only when an analyst POSTs a feature record
      to /api/ai/analyze or a script calls FastAPI. The replay demo uses /predict/eval, which by design never stores,
      alerts or blocks.
Why it matters: "Real-time network intrusion detection" is not what the system does.
Fix: Reword to "on-demand / replay evaluation of flow records", or add a labelled replay feed into the persisted path.
Proof of fix: Demo script drives flows into the persisted path; UI shows them labelled "replay".
```

```
ID: CORE-004 | Priority: P1 | Label: CONFIRMED (static + ran: read seed Q-table)
Where: backend/services/honeypotService.js:128,288-291; ai-engine/rl_engine/deception_scorer.py:46-65,181-209;
       ai-engine/inference/deception.py:17-96; honeypot/switch_profile.py (no caller); honeypot/cowrie/cowrie.cfg
What: The Q-learning "adaptive deception" adapts nothing:
  - The recommended profile is stored on the session and never applied (switch_profile.py is a manual CLI with no
    caller; cowrie.cfg is a fixed CentOS persona while the learner is told "ubuntu_22").
  - State is always 'ubuntu_22' (recommendedProfile is unset when the payload is built), so one Q-row learns.
  - update(prev, next_p, reward, next_p) credits a reward earned under the old profile to the profile just chosen,
    whose effect was never observed; next_state == action makes it a bandit, not an MDP.
  - Runtime Q-table goes to a per-process temp dir unless SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1 → learning resets on
    every restart (re-seeded from models/q_table.json).
Why it matters: This is the "self-evolving / adaptive honeypot" core of the paper.
Fix (honest minimum): "tabular Q-learning profile recommender (prototype); recommendations are logged, not applied".
     Code fix: state = profile active during the session; update after the next session under that action; persist
     to a configured path; apply via switch_profile in a lab.
Proof of fix: Test: two sequential sessions → Q[s_prev][a] updated with the reward of the session that ran under a.
```

```
ID: SEC-002 | Priority: P1 | Label: CONFIRMED (static)
Where: backend/routes/aiEngine.js:11-30,195-201 (POST /api/ai/predictions, internalOrUserAuth);
       backend/services/aiService.js:38-117; backend/routes/honeypotIngest.js:7-14,241-252
What: Either static service key (HONEYPOT_API_KEY — leaked per SEC-001 — or SENTINEL_KEY), or any analyst JWT, can
      POST an arbitrary "AI prediction". req.body goes straight into AIPrediction.create (mass assignment) and into a
      ThreatLog with caller-chosen sourceIP, predictedClass, threatScore. With autoBlock on and score ≥ 0.92 the IP
      joins the permanent deny-list with no policy check. /ingest/command trusts caller-supplied intent/isMalware.
Why it matters: A key holder (or analyst) fabricates "model detections" shown in AI Analytics as genuine output,
      raises CRITICAL alerts, blocks arbitrary IPs from the honeypot, and pollutes verification/training data.
Fix: Accept only SENTINEL_KEY on /api/ai/predictions; whitelist fields; separate key per producer; reclassify
     intent server-side on /command; constant-time compare.
Proof of fix: Supertest: HONEYPOT_API_KEY → 403; unknown fields dropped; analyst JWT → 403.
```

```
ID: F1-001 | Priority: P1 | Label: CONFIRMED (static) + prior-report
Where: honeypot/cowrie/cowrie.cfg (no [output_sentinel] section); honeypot/parsers/log_parser.py:16-22 (/opt/cowrie);
       docs/DATABASE_HEALTH_REPORT.md:319, docs/DATABASE_GUIDE.md:322 (prior-report)
What: Live Cowrie telemetry cannot currently flow: Cowrie needs Linux, Docker was removed, the shipped config does not
      enable the output plugin. Prior reports record one real lab session (Docker bridge, 3,383 automated logins) and
      seven synthetic demo-* sessions in sentinel-db.
Why it matters: "Live honeypot telemetry" can today only be shown with the demo generator or trigger_block.js.
Fix: Run Cowrie in WSL/VM and record one end-to-end run, or reword to "validated with one lab session + replays".
Proof of fix: Fresh Cowrie session visible in UI with a DB row whose sessionId matches cowrie.json.
```

```
ID: CORE-005 | Priority: P2 | Label: CONFIRMED (static)
Where: backend/utils/securityEventBus.js (~550 lines), backend/routes/systemOutbox.js
What: The durable event bus / outbox has no producers outside tests; all business events are direct, non-durable
      socket emits. Containment-action lifecycle events never reach clients.
Fix: Route emits through the bus, or delete it and drop the reliability claim in docs/phase-7-*.
```

```
ID: CORE-006 | Priority: P2 | Label: LIKELY (static)
Where: backend/websocket/socketManager.js:24-29 (every socket joins 'all'/'threat_subscribers'), :268-300
What: Admins/analysts receive each honeypot event, live_feed_event and ai_prediction twice (raw + redacted), so the
      feed shows duplicates incl. "Command: [REDACTED_COMMAND]". Emitted with no UI listener: ip_unblocked,
      malware_download, critical_alert. Not covered by tests (scratch/verify_analyst_feed.mjs takes the first frame).
Fix: Keep privileged sockets out of 'all', or send redacted copies only to 'viewer'.
Proof of fix: Socket test: admin gets exactly one honeypot_command per ingest.
```

```
ID: CORE-007 | Priority: P2 | Label: CONFIRMED (static)
Where: backend/services/honeypotService.js:386-402 (getNodeStatus)
What: Four honeypot nodes are hard-coded (SSH-COWRIE-01, HTTP-LURE-02, FTP-TRAP-03, SMTP-DECOY-04); only the SSH
      Cowrie node exists in the repo. The others always read "idle".
Fix: Remove or label "planned".
```

```
ID: ML-003 | Priority: P2 | Label: CONFIRMED (static)
Where: ai-engine/inference/main.py:77-101 (Record defaults, extra="allow")
What: Missing flow features are silently defaulted (e.g. syn_flag_count=1, flow_duration=1000); a record with only
      sourceIP gets a confident prediction instead of a 422.
Fix: Make the 53 features required on /predict*, or report which were defaulted.
```

```
ID: SEC-003 | Priority: P3 | Label: CONFIRMED (static)
Where: backend/routes/honeypotIngest.js:10-11; backend/routes/aiEngine.js:15-18
What: API keys compared with === (not constant-time). Fix: crypto.timingSafeEqual.
```

```
ID: DOC-002 | Priority: P3 | Label: CONFIRMED (static)
Where: docs/ENROLLMENT_POLICY_20261015.md vs backend/controllers/userController.js:32, middleware/auth.js:36-43
What: Doc says forced first-login password change is not implemented; it is.
```

---

## Re-verification at `a5856b7` (2026-10-22)

16 commits landed after Stage 2 (`e5318ac`…`a5856b7`). Every earlier finding was re-checked on the new HEAD.

| ID | Now | Evidence |
|---|---|---|
| SEC-001 | **OPEN, escalated to P0** | `git branch -r --contains 315700c` → `origin/db-fixes` (pushed); `backend/.env` and `deployment/.env.demo` still hold the leaked value (match flag only) |
| OPS-001 | FIXED | `utils/destructiveGuard.js` |
| TEST-001 / TEST-002 / CI-001 | FIXED | `playwright.config.js:61`; `e2e.yml:35-36`; `ci.yml:77` |
| ML-001 | **WITHDRAWN** | Time-of-day columns are zero in every CICIDS2017 training row (`features.py:496-498`); importances are 0.0 in RF v2, RF v3, XGB v1 (ran, read-only load) |
| ML-002 | FIXED | `ai-engine/models/registry.json` pins the served files by sha256; root `models/README.md` marks the archive |
| DOC-001 / DOC-002 / CFG-001 | FIXED | README:227; enrollment doc; `validateEnv.js` |
| HYG-001 | PARTLY FIXED | `.bak`/`.orig` backend files deleted; ~30 superseded model files remain in `ai-engine/models` |
| CORE-001 | MOSTLY FIXED | Auto-block → `requestContainment` (`containmentService.js:895`); manual paths still DB-only → CORE-001b |
| CORE-002 | FIXED | Honeypot sessions are rule-classified (`predictor.py:529-575`, `classificationMethod: honeypot_rules`) |
| CORE-003 | FIXED as replay | `replay_cicids.py --target backend` posts to `/api/ai/analyze`; no live capture (claim → CLAIM-001) |
| CORE-004 | PARTLY FIXED | Credit assignment, stable Q-table path (`deception_scorer.py:47-66`), `deception_rotator.py`; never run against live Cowrie |
| CORE-005 | FIXED | `socketManager.js:110-120` records every delivered event on the bus |
| CORE-006 / CORE-007 | FIXED | Redacted copies viewer-only; single node |
| SEC-002 / SEC-003 / ML-003 | FIXED | Fix batch 1 still present |
| F1-001 | OPEN | No Cowrie service in `docker-compose.yml`; no Linux host |

---

## Stage 3–7 findings (at `a5856b7`)

```
ID: CLAIM-001 | Priority: P1 | Label: CONFIRMED (static)
Where: paper_text.txt (abstract; Tab II; Tab IV; §VIII; §XI-B/D/G/H; §XIII), README.md:30,44,46,48,72-75,139-146,
       frontend/src/pages/Landing.jsx:133-134,198-218, Features.jsx:4-7, About.jsx:18-28
What: Text describes RF v2 as deployed (XGB xgb_cicids_v1 is, registry.json); XGB as synthetic-only / not deployed;
      4 files / 6 classes / 46 features (8 / 10 / 53); an SGD partial_fit learner (no code path, features.py:598);
      MITRE tagging on every detection (honeypot only, honeypotService.js:175); live network events (replay only);
      a Docker Compose deployment (file exists, never run here, no Cowrie service); an Ubuntu Cowrie persona (CentOS);
      RF/IF/SHAP on honeypot sessions (rules); a hard-coded "REAL MODE … live packet" terminal; SOAR playbooks,
      session termination, sub-100 ms latency (none exist / unmeasured).
      The paper also UNDERSTATES current auth (§XI-B) and tests (§XI-G, Ph8).
Fix: Wording list in REPORT.md §3.
```

```
ID: ML-004 | Priority: P1 | Label: CONFIRMED (static) + prior-report
Where: xgb_classifier_xgb_cicids_v1_meta.json class_counts; docs/C1_EVALUATION_PLAN_AND_RESULTS.md §3
What: RF-recipe leave-one-day-out attack detection 0.03–7.7%; deployed-XGB LODO not measured (UNKNOWN). Test support:
      SQLi 4, RCE 2, Lateral 7, Data Exfiltration 0. Zero-day claims unsupported.
Fix: Report chronological + LODO + per-class support; drop zero-day language.
```

```
ID: SEC-004 | Priority: P2 (P1 once real enforcement is enabled) | Label: LIKELY (static)
Where: predictor.py:541-543 (rule score + 0.02/command), honeypotService closure → containmentService.js:895,
       containmentPolicyService.js PROTECTED_* (loopback/link-local/multicast only by default)
What: Any HONEYPOT_API_KEY holder can open a session for any sourceIP, send enough commands to pass 0.92 and close it;
      with autoBlock on, that IP is deny-listed and sent to the adapter. With the Windows Firewall adapter enabled,
      that becomes a real host rule against e.g. the gateway or an analyst workstation, unless
      CONTAINMENT_PROTECTED_TARGETS is set. An auto-block cap exists (commit b282021): it limits volume, not targets.
Fix: Rotate the key (SEC-001); set CONTAINMENT_PROTECTED_TARGETS; require manual approval for RFC1918 auto-blocks.
```

```
ID: OPS-002 | Priority: P2 | Label: CONFIRMED (static)
Where: docker-compose.yml backend: NODE_ENV=development, ports "5000:5000"; securityTopology.js:45 (any transport
       accepted outside production), authCookies.js:24 (Secure cookies only in production/https), server.js:226
What: The compose deployment publishes the whole API on all interfaces in development mode, so logins and refresh
      cookies travel over plain HTTP to whoever can reach port 5000.
Fix: NODE_ENV=production behind a TLS proxy, or publish 127.0.0.1:5000 and expose only the ingest path to the honeypot.
```

```
ID: CORE-001b | Priority: P2 | Label: CONFIRMED (static)
Where: backend/services/containmentService.js blockThreat / blockIPManual
What: Manual Block and block-ip still only write BlockedIP/ThreatLog (no adapter, no ContainmentAction). Labelled
      honestly in the UI since fix batch 1.
Fix: Route through requestContainment like auto-block.
```

```
ID: ML-005 | Priority: P2 | Label: CONFIRMED (static)
Where: xgb_classifier_xgb_cicids_v1_meta.json provenance.git_dirty=true, evaluation.independent_holdout=false
What: The served model was trained from an uncommitted tree on a random split; its exact recipe is not reproducible
      from a commit.
Fix: Retrain from a clean commit with the chronological recipe; record the split in meta.
```

```
ID: RET-001 | Priority: P2 | Label: CONFIRMED (static)
Where: ai-engine/training/retrain_from_samples.py; models/registry_history.jsonl (only backfill/register_model.py)
What: Human-gated retraining exists but has never promoted a model.
Fix: Run it once end to end and record the registry_history entry.
```

```
ID: TEST-003 | Priority: P2 | Label: CONFIRMED (static)
Where: backend/tests (36 files mock models, 14 mock AI service), ai-engine/tests, frontend/e2e/realtime.spec.js
What: No automated test runs Express ↔ FastAPI ↔ Mongo together; the firewall adapter is tested only for refusal;
      Cowrie only via offline contracts; realtime E2E injects events via the test emit hook.
Fix: One compose-based CI job replaying flows end to end.
```

```
ID: TEST-004 | Priority: P2 | Label: CONFIRMED
What: The auditor's green runs (Jest 948, pytest 335, frontend 36) predate commits e5318ac…a5856b7. Pass status at
      HEAD is not established by this audit.
Fix: Re-run (requires approval under the audit rules).
```

```
ID: OPS-003 | P3 | CONFIRMED (static) — MongoDB in compose has no auth (internal network only).
ID: OPS-004 | P3 | LIKELY (static) — honeypot/collectors/session_collector.js:8 sessionMap only shrinks on collector
            closure; sessions closed by the sweep or never closed stay in memory (sessionId attacker-chosen, ≤128 chars).
ID: EVT-001 | P3 | CONFIRMED (static) — ip_unblocked and critical_alert are emitted with no frontend listener.
ID: SEC-005 | P3 | CONFIRMED (static) — helmet CSP disabled (server.js:69).
ID: DEP-001 | P3 | CONFIRMED (static) — early-2024 Python pins (fastapi 0.109.2, requests 2.31.0, scikit-learn 1.4.0),
            pytest in runtime requirements; experiment pickles saved with scikit-learn 1.7.2 load under 1.4.0 with
            InconsistentVersionWarning (ran). No CVE claims: pip-audit / npm audit not run (needs network).
```

Strengths confirmed in Stage 4 (no finding): HS256 pinned, access tokens capped at 900 s, DB-backed sessions with
revocation and inactivity timeout; Socket.IO handshake + per-packet re-auth; every router guarded; express-mongo-sanitize
+ regex escaping + ObjectId validation; 10 kB body limit; rate limits on auth and machine routes; 5xx messages
generic; no dangerouslySetInnerHTML; AI engine not published in compose, read-only container, cap_drop ALL; model
files SHA-256 pinned (registry + optional MODEL_REGISTRY_SHA256); /metrics token- or loopback-only; reload needs the
admin key when configured.
