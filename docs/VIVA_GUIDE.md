# SentinelAI viva and presentation guide

Examiner-friendly explanations and answers. Every number comes from a measured run (sources in
[`FINAL_PROJECT_GUIDE.md`](FINAL_PROJECT_GUIDE.md) §3 and §11); where something was not measured, the answer says so.
The demo procedure itself is [`DEMO_ABC_RUNBOOK.md`](DEMO_ABC_RUNBOOK.md).

## 1. The 90-second introduction

> SentinelAI is a security-operations prototype that combines three ideas in one dashboard. First, **deception**: a
> real Cowrie SSH honeypot captures attacker sessions, maps their commands to MITRE ATT&CK, and a small Q-learning
> recommender chooses which fake server persona to show next. Second, **machine-learning detection**: network flows
> are classified by an XGBoost model with an Isolation Forest anomaly check, and every alert can be explained with
> SHAP, computed from the exact feature vector that produced it. Third, **policy-governed response**: high-risk
> threats can be contained through a state machine with protected targets, expiry, audit and rollback; enforcement is
> deliberately simulated. It is a React, Node.js and Python system with MongoDB and real-time Socket.IO updates.
> I will be honest about its limits: the model scores about 99 % on a random split of CICIDS2017 but misses most
> attacks from days and tools it never saw, flows are replayed from a dataset rather than captured live, and the
> learner's benefit has not been measured.

## 2. Architecture in one breath

Browser → **backend** (Express: authentication, RBAC, threat pipeline, containment, Socket.IO) → **AI engine**
(FastAPI, loopback only, service key) and **MongoDB**. Cowrie runs in WSL; a parser ships its log to the backend, and
Cowrie's blocker plugin reads the backend's deny-list. Diagram: [`FINAL_PROJECT_GUIDE.md`](FINAL_PROJECT_GUIDE.md) §2.

Why this split: the model runs in Python where the ML libraries are; the backend owns security decisions so the
engine never faces the network; real-time updates and per-role redaction live in one place (the backend).

## 3. Demo A: Honeypot Intelligence (what happens, step by step)

1. You SSH into Cowrie on port 2222 with lab credentials. Cowrie fakes an Ubuntu shell; nothing executes on a real
   host.
2. Cowrie writes JSON events; the parser posts them to `/api/honeypot/ingest` (idempotent by event id). The dashboard
   shows the session and each command live (Socket.IO).
3. When the session closes the backend maps commands to ATT&CK (e.g. `uname` → T1082, `whoami` → T1033,
   `/etc/passwd` → T1003.008), classifies intent with rules, gets a threat score from the engine and a deception
   score from the learner.
4. The learner updates its Q-table for the persona that served the session and draws one recommendation, stored as a
   decision record.
5. `cowrie-demo-mode.sh rotate --once` applies it: rewrites `cowrie.cfg` for the new persona, restarts Cowrie, marks
   the decision `APPLIED`. The next SSH session shows the new hostname and is credited to that persona.

Point out: the classification here is **rule-based** (`honeypot_rules`), not the network model.

## 4. Demo B: AI Threat Detection

1. `replay_cicids.py` sends **recorded CICIDS2017 flows** to `/api/ai/analyze`. Say: replayed, not live capture.
2. The engine validates each record against the 53-feature schema (malformed → 422; many defaulted features →
   flagged incomplete, never auto-blocked).
3. XGBoost gives class probabilities; the Isolation Forest gives an anomaly score; both form the threat score.
4. Non-BENIGN at or above **0.90** → ThreatLog (HIGH) + alert; at or above **0.92** → CRITICAL.
5. **Explain** on a threat: the backend sends that prediction's stored vector to the engine, which re-scores it and
   refuses unless class, score and model version are identical, then returns SHAP contributions.

## 5. Demo C: Autonomous Incident Response

1. Admin enables auto-block (off by default).
2. A flow scoring ≥ 0.92 on an unprotected address creates a containment action (`AI Auto-Block`).
3. Policy runs first: loopback, link-local and configured protected targets are refused; degraded or incomplete
   predictions never auto-block.
4. State machine `REQUESTED → VALIDATING → APPROVED → APPLYING → ACTIVE`; the **mock adapter** records a simulated
   rule; the honeypot's deny-list is the only real enforcement (Cowrie refuses that IP).
5. Audit records at every step; the operator rolls back (`ROLLED_BACK`, deny-list row removed); a TTL rolls back by
   itself.
6. Engine outage: flows are stored as `DEGRADED` (MEDIUM, never blocked), one "AI Engine" alert, `/health` 503, the
   dashboard keeps working; recovery is automatic.

## 6. Why XGBoost and Isolation Forest

- **XGBoost:** tabular flow features with mixed scales and strong interactions; gradient-boosted trees handle that
  without scaling, train quickly on CPU, give calibrated-enough probabilities for thresholds, and allow exact,
  fast TreeSHAP explanations. It replaced an earlier Random Forest (still reported in the paper) after evaluation.
- **Isolation Forest:** unsupervised, so it can flag flows unlike the training data that the classifier would
  confidently call benign. Those go to an analyst review queue rather than becoming threats.
- **Honest limit:** neither fixes generalisation to unseen attack days (3–51 % recall); the anomaly tier was not
  shown to recover those attacks.

## 7. How Q-learning works in SentinelAI

- **State:** the persona that served the last session. **Actions:** the next persona (5 servable Linux personas;
  Windows is excluded because Cowrie cannot fake a Windows shell).
- **Reward** per closed session: engagement (log of duration, commands, intent bonuses such as malware download,
  IOCs, successful login) minus a penalty if the attacker ran fingerprinting commands (`systemd-detect-virt`,
  `/proc/1/cgroup`, …); clipped to [-10, 20].
- **Update:** `Q(s,a) ← Q(s,a) + α [r + γ·max Q(s',·) − Q(s,a)]` with α 0.1, γ 0.9.
- **Policy:** ε-greedy, ε starts at 0.2 and decays with episodes to a floor of 0.05 so it keeps exploring. A UCB1
  bandit policy is available (`DECEPTION_POLICY=ucb1`) because, with the state being only the last persona, the
  problem is close to a multi-armed bandit.
- **Honest limit:** we have **not** measured whether rotation increases attacker engagement compared with a fixed
  persona; that needs a controlled study with real attackers. What is verified is that the mechanism works end to
  end (decision persisted, applied, credited).

## 8. How SHAP explanations work here

- SHAP assigns each feature a contribution so that **base value + sum of contributions = the model's output**
  (here the XGBoost margin in log-odds for the predicted class). TreeSHAP computes this exactly for tree ensembles.
- SentinelAI stores the 53-feature vector with every prediction. An explanation re-scores that vector and is shown
  only if the class, score and model version reproduce, so the bars always belong to the alert on screen.
- Additivity is checked by a test; explanations are identical across thread settings (batch 13 test).
- Limit: SHAP explains the classifier, not the anomaly term of the threat score; contributions show association
  inside the model, not causation in the network.

## 9. Simulated versus real enforcement

| | Real | Simulated |
|---|---|---|
| Containment decision, policy checks, state machine, audit, rollback | ✔ | |
| Honeypot deny-list (Cowrie refuses the IP) | ✔ | |
| Host firewall rule | | ✔ mock adapter records it; the Windows Firewall adapter is disabled and has never run live |

Say: "the decision and its record are real; enforcement on the host is simulated."

## 10. Accuracy versus cross-day generalisation

- Random 80/20 split: 98.97 % accuracy, macro F1 0.874. Optimistic because flows from the same attack burst land on
  both sides.
- Train Monday–Wednesday, test Thursday–Friday: attack recall 50.6 %.
- Leave one day out: 3.1–33.4 % attack recall; a model trained on one DDoS tool detected 0 % of other DoS tools.
- Conclusion: excellent at recognising attacks like those it was trained on; **not** a detector of new attacks.
  This is the most important limitation and is stated in the README.

## 11. Contribution and novelty (and its limits)

What the project contributes:
- An integrated, working pipeline: honeypot intelligence, ML detection with per-alert verified explanations, and
  policy-governed containment with rollback, all with role-based redaction and real-time updates.
- Engineering rigour: model hash verification and golden-set reproduction at startup, pre-registered evaluation
  with protected test days, failure-mode testing (engine/database outages), extensive automated tests.
- An honest evaluation that quantifies the generalisation gap.

Limits on novelty: each component (Cowrie, XGBoost on CICIDS2017, SHAP, Q-learning for honeypots) exists in the
literature; the contribution is integration and evaluation, not a new algorithm. The RL benefit is unmeasured.

## 12. Major engineering challenges and how they were solved

| Challenge | Solution (evidence) |
|---|---|
| Dataset leakage inflated accuracy | De-duplication, chronological and leave-one-day-out evaluation; protected days never touched |
| Model files silently changing | SHA-256 registry + golden-set reproduction at startup; Git attribute `-text` so line endings never alter them |
| Explanations that might not match the alert | Store the feature vector; re-score and refuse on any mismatch |
| Engine CPU saturation under load (PERF-001) | Single-threaded per-request inference: engine CPU ~60 % → ~8 % |
| Dashboards losing their live feed after a database outage (WS-001/WS-002) | Retried handshakes with backoff; catch-up of missed threats from the role-redacted API |
| Safe containment | Policy before action, protected targets, TTL, rollback, mock adapter by default |
| Session security | Rotating refresh cookies, CSRF, socket re-authorisation, revocation that disconnects sockets |

## 13. Difficult questions and accurate answers

**"Your model is 99 % accurate, so it works?"** On a random split, yes, but that split is optimistic. On unseen days
recall is 3–51 %, so it would miss most new attacks. I report both.

**"Is this a real IDS?"** No. Flows are replayed from CICIDS2017; there is no packet capture. The honeypot part is
real traffic.

**"Did you block attackers on the host?"** No. The containment logic is real; the firewall action is simulated by a
mock adapter. Only the honeypot refuses deny-listed IPs.

**"Does the reinforcement learning help?"** Unknown. The mechanism works and is tested; its effect on attacker
engagement has not been measured. Its state is only the previous persona, so it behaves almost like a bandit.

**"Why not deep learning?"** Tabular features, limited compute, need for exact explanations and fast inference; tree
ensembles are the standard strong baseline. Deep models would not fix the cross-day generalisation problem by
themselves.

**"How do you know the explanation matches the alert?"** The stored vector is re-scored; if class, score or model
version differ the explanation is refused.

**"What happens if the AI engine crashes during an attack?"** The flow is stored as DEGRADED (never blocked), an alert
is raised, health reports 503, and scoring resumes automatically when the engine returns (measured).

**"Could a viewer see attacker IPs?"** No. Viewer API responses and socket events are redacted on the server (last
octet masked, commands removed); tested end to end.

**"Is it production-ready?"** No. No TLS, Docker deployment untested, credentials once committed to history (SEC-001,
risk accepted), simulated enforcement, single host.

**"What was the hardest bug?"** For example, dashboards silently stopped receiving live threats after a database
outage: the server closes sockets when it cannot verify sessions, and Socket.IO does not retry that. Fixed with a
retry policy and a catch-up of missed threats, both covered by tests that failed before the fix.

## 14. Presentation checklist

- [ ] `register_model.py --check` OK; `node scripts/integration/run_integration.cjs --cowrie` all passed (~5 min)
- [ ] `start-demo.ps1`: three `UP`; WSL `cowrie-demo-mode.sh on` → `status` shows check-block HTTP 200
- [ ] Demo accounts work (passwords on your cue card only)
- [ ] Settings: auto-block state as intended; your WSL-side IP not deny-listed
- [ ] `cowrie.cfg.pre-demo` backup taken
- [ ] Say early: flows replayed, enforcement simulated, RL benefit unmeasured, cross-day recall low
- [ ] After: `stop-demo.ps1`, `cowrie-demo-mode.sh off`, restore persona if changed
