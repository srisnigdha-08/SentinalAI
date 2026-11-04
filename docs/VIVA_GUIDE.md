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

---

# Part 2 — Question bank (beginner-friendly, technically exact)

Numbers: [`PROJECT_METRICS.md`](PROJECT_METRICS.md). Where a question is hard, a **short** (one sentence),
**medium** (what an examiner usually wants) and **detailed** answer are given.

## A. Basic cybersecurity

**A1. What is the difference between an IDS and an IPS?** An IDS detects and alerts; an IPS sits in the traffic path
and blocks. SentinelAI detects (IDS-like) and can decide to contain, but host blocking is simulated; only the honeypot
actually refuses connections.

**A2. What is a false positive and why does it matter here?** A benign flow flagged as an attack. Analysts drown in
them, and automatically blocking a false positive harms legitimate users. That is why auto-block is off by default,
uses a stricter line (0.92) than alerting (0.90), checks protected targets and always has expiry and rollback.

**A3. What is MITRE ATT&CK?** A public knowledge base of attacker tactics and techniques with IDs. We map honeypot
commands to technique IDs, e.g. `uname` → T1082 System Information Discovery, `whoami` → T1033, reading
`/etc/passwd` → T1003.008.

**A4. What is defence in depth in your system?** Several independent layers: authentication and RBAC, CSRF, rate
limiting, server-side redaction, model integrity checks, containment policy before action, audit logs.

**A5. What is a honeypot?** A decoy system with no legitimate users, so any interaction is suspicious. It reveals
attacker behaviour without risking real assets.

## B. Networking and honeypots

**B1. What is a network flow?** A summary of one bidirectional conversation (addresses, ports, protocol plus
statistics such as packet counts, sizes, inter-arrival times, TCP flags and window sizes). CICIDS2017 provides flows
extracted by CICFlowMeter.

**B2. What kind of honeypot is Cowrie?** Medium-interaction: it implements SSH and an emulated shell with a fake
filesystem; commands do not run on a real operating system.

**B3. Why run Cowrie in WSL and on port 2222?** It is a Linux application, and WSL keeps it apart from Windows. Port
2222 avoids needing root for port 22. In demo mode it listens only on the WSL address, which is not reachable from the
LAN.

**B4. How does the honeypot enforce a block?** Cowrie's blocker plugin reads the backend's deny-list
(`check-block`, HTTP 200 in the demo) and refuses connections from listed IPs. That is the only real enforcement.

**B5. How could an attacker detect the honeypot?** Emulation gaps, probed with commands such as
`systemd-detect-virt`, reading `/proc/1/cgroup`, or searching for `cowrie`. The reward penalises sessions with such
fingerprinting commands.

## C. Machine learning

**C1. Supervised versus unsupervised in SentinelAI?** XGBoost is supervised (learns labelled classes); the Isolation
Forest is unsupervised (learns what benign traffic looks like and scores outliers).

**C2. What are precision, recall and F1?** Precision: of the flows we called attacks, how many were. Recall: of the
real attacks, how many we caught. F1: their harmonic mean. Macro F1 averages classes equally (0.874 here), so rare weak
classes pull it down; weighted F1 (0.991) is dominated by the large classes.

**C3. Why did you de-duplicate the data?** 23,481 exact duplicate rows would otherwise land in both the training and
the test set and inflate scores.

**C4. What is data leakage and where can it hide?** Information from the test set reaching training. With a random
split, flows from the same attack burst appear on both sides, so the test measures recognition of near-copies.

**C5. How did you handle class imbalance?** Per-class caps before training and balanced sample weights in XGBoost; we
report per-class metrics and macro F1, and we flag classes with fewer than 10 test flows as not meaningful.

**C6. What is overfitting and do you have it?** Fitting the training distribution too closely. The day held-out
results (3–51 % recall) show the model over-fits to the tools and capture conditions of each day.

## D. XGBoost and Isolation Forest

**D1. How does XGBoost work?** It builds decision trees one after another; each new tree fits the errors (gradients)
of the current ensemble, with regularisation. Served recipe: 200 trees, depth 6, learning rate 0.1, seed 42, inputs
scaled with a StandardScaler fitted on training rows only.

**D2. Why XGBoost rather than a neural network?** Tabular features, CPU-only deployment, millisecond single-flow
latency and exact TreeSHAP explanations. A deep model would not by itself solve the cross-day problem.

**D3. How does an Isolation Forest work?** It isolates points with random splits; anomalies need fewer splits (a
shorter average path length). Ours is trained on benign flows with contamination 0.1.

**D4. How are the two combined?** `blend = 0.7·c + 0.3·a` (c = classifier strength, a = anomaly signal, both in
0–1). For a predicted attack the score is `max(c, blend)`, so the anomaly signal can only raise it; for BENIGN it is
`blend`. Benign-predicted but anomalous flows go to an analyst review queue, never directly to an alert.

**D5. What do 0.90 and 0.92 mean?** 0.90 is the alert line (threat plus alert, HIGH); 0.92 is the block line
(CRITICAL; contained if auto-block is on). 0.90 was the lowest line meeting a 0.1 % benign-alert target on
chronological validation data.

## E. SHAP

**E1. What is a Shapley value?** From cooperative game theory: a feature's average marginal contribution over all
orders in which features could be added. SHAP applies it to model predictions.

**E2. Why TreeSHAP?** It computes exact Shapley values for tree ensembles in polynomial time, fast enough per alert
(explanation p95 48 ms).

**E3. What does a bar mean?** How much that feature pushed the classifier's log-odds for the predicted class up (red)
or down (blue) relative to the base value. They add up exactly: base + Σ contributions = margin (rehearsal: base 0.246,
total 8.26).

**E4. How do you guarantee the explanation belongs to the alert?** Each prediction stores its 53-feature vector; the
engine re-scores it and refuses unless class, score and model version are identical.

**E5. Limits of SHAP here?** It explains the classifier, not the anomaly term; it shows association inside the model,
not causation in the network.

## F. Reinforcement learning

**F1. Explain Q-learning.** An agent learns Q(s,a), the value of action a in state s, with the update
`Q ← Q + α(r + γ·max Q(s',·) − Q)`. We use α 0.1 and γ 0.9.

**F2. What are the state, action and reward?** State: the persona that served the last session. Action: the next
persona (5 Linux personas). Reward: engagement of the closed session (duration, commands, intent bonuses, IOCs,
successful login) minus 5 for fingerprinting, clipped to [−10, 20].

**F3. Exploration versus exploitation?** ε-greedy: with probability ε (0.2, decaying to a floor of 0.05) try a random
persona, otherwise the best known one. The floor keeps exploring because attacker behaviour changes.

**F4. Is this really reinforcement learning?** *Short:* technically yes, practically close to a bandit.
*Medium:* the state is only the previous persona, so actions barely influence future states; a multi-armed bandit
(UCB1, also implemented) is the more natural model. *Detailed:* full RL would need state that the action changes,
e.g. attacker stage or session history; that is future work.

**F5. Does it improve engagement?** *Short:* not measured. *Medium:* the mechanism works end to end (decision drawn,
persisted, applied, credited; rehearsed live), but proving a benefit needs a controlled comparison with a fixed
persona on real attacker traffic. *Detailed:* the table was warm-started from a synthetic seed, the lab sees very few
real sessions, and the reward is a proxy; any effect claim would be unsupported.

## G. Backend architecture

**G1. Why a separate Node backend and Python engine?** The ML libraries live in Python; the backend owns security,
persistence and real-time events, so the engine never faces the network (loopback only, service key).

**G2. How do sessions work?** A short-lived JWT access token kept in memory; a rotating refresh token in an
`httpOnly`, `SameSite=Strict` cookie; a CSRF token on authentication mutations; reusing an old refresh token revokes
the session.

**G3. What happens if the engine is down?** Calls time out after 10 s; after 5 failures a circuit breaker opens (fast
failure) and resets after 30 s; flows are stored as DEGRADED (MEDIUM, never blocked) and one alert is raised.
Rehearsed live: `restart-engine.ps1` brought it back in 11 s with no backend restart.

**G4. How is containment made safe?** Policy before action, protected targets, one active action per target (unique
sparse lock index), TTL expiry, operator rollback, compensating actions on failure, audit at every step.

## H. Frontend and WebSockets

**H1. Why Socket.IO instead of polling?** Push updates with low latency and per-role rooms; the dashboard still
refreshes some summaries every 30 s.

**H2. How do roles affect socket data?** Sockets join rooms only after the server verifies the session; privileged
rooms get raw events, the viewer room gets redacted copies (last IPv4 octet `xxx`, commands removed).

**H3. What happens when the connection drops?** Socket.IO reconnects transport drops by itself; after a server-side
disconnect (e.g. a database outage) the dashboard retries with backoff, rejoins its rooms and fetches the threats it
missed from the API (at most 20), de-duplicated by threat id.

**H4. Can a revoked session keep receiving events?** No. Sessions are re-checked every 15 s and on revocation the
server disconnects the socket; its reconnect is refused.

## I. Database

**I1. Why MongoDB?** Flexible documents for heterogeneous security events (sessions with nested commands, predictions
with their feature vectors) and good Node integration.

**I2. Name an important index.** `containmentactions.targetLock`: unique and sparse, so only one active containment
per target can exist; finished actions release the lock. (Batch 15 fixed the backup tool, which had dropped the
`sparse` option and therefore lost this index on restore.)

**I3. How are demo and real data separated?** The demo uses `sentinel-demo` and its own Q-table; tests use throwaway
databases; the seed and reset scripts refuse to run without naming the database.

## J. Testing

**J1. How is the system tested?** Unit tests (Jest, pytest, node:test), browser E2E (Playwright, three engines),
cross-service integration with live Cowrie, a load and failure harness, a clean-clone installation test, and CI with
7 jobs.

**J2. What is the golden set?** 20 fixed feature vectors whose outputs the engine must reproduce at start-up; with the
SHA-256 registry it proves the served model is the one that was evaluated.

**J3. Give an example of a bug your tests found.** The demo rehearsal found that unblocking an address detected more
than once left its earlier detections BLOCKED (CONT-001); a real-database test reproduced it before the fix.

## K. Security limitations

**K1. Is SentinelAI production-ready?** No: no TLS, Docker untested, single host, simulated enforcement, and
credentials once committed to Git history (SEC-001, risk accepted, not rotated).

**K2. What is SEC-001?** Credentials were committed in the repository's history. Fixing it needs rotation and history
clean-up; the owner accepted the risk for this project and it stays documented as open.

**K3. Biggest risk if deployed as it is?** Over-trusting the detector: it misses most unseen attacks.

## L. Research methodology

**L1. How did you avoid fooling yourself?** De-duplication, chronological and day held-out splits, confidence
intervals, pre-registered criteria for candidate models, and four CSE-CIC-IDS2018 days kept untouched for one
external test.

**L2. Why report negative results?** They are the main research finding: random-split accuracy overstates IDS
capability. Hiding them would mislead.

**L3. Why not use the protected 2018 days now?** A one-shot external test is only valid if nothing was tuned on it;
running it is a separate experiment that needs approval.

## M. Performance metrics

**M1. How fast is inference?** Single flow p95 about 30 ms; explanation p95 48 ms; engine ready in 5–6 s.

**M2. Throughput?** Backend end to end 75–98 requests/s at 20 concurrent clients with no errors; engine CPU about 8 %
of the machine after PERF-001.

**M3. What was PERF-001?** Models saved with "use all cores" started thread pools for every single-row request and
competed under load; running each request single-threaded cut engine CPU about eightfold with identical predictions.

## N. Project contributions

**N1. What is your contribution?** An integrated, tested pipeline (deception, explainable detection, governed
response) with verified per-alert explanations, and an honest quantification of the generalisation gap.

**N2. What would you do with six more months?** Live flow capture; more diverse training data with day/dataset
held-out acceptance; a controlled persona study; correlation before blocking; deployment hardening.

## O. The hardest examiner questions

**O1. "99 % accuracy but 3 % recall on Tuesday — which number is true?"**
*Short:* both, for different questions. *Medium:* 99 % answers "does it recognise attacks like its training data?";
3–51 % answers "does it detect attack days it never saw?". The second is what an IDS needs, and it is poor.
*Detailed:* most classes were captured with one tool on one day; a random split leaks bursts across training and
test; held-out days remove that leakage. We report both, with confidence intervals.

**O2. "You replay a dataset. Isn't this just a classifier demo?"**
*Short:* the flows are replayed, but everything after them is the real system. *Medium:* replayed records go through
the same API, validation, model, storage, alerting, explanation and containment that live input would; only capture
is missing. *Detailed:* we say "recorded CICIDS2017 flows replayed" every time; live capture is future work.

**O3. "Your containment is fake."**
*Short:* the decision is real; the host action is simulated. *Medium:* policy, state machine, audit, expiry and
rollback are real and tested; the mock adapter stands in for the firewall; the honeypot's refusal of a deny-listed IP
is real (shown live). *Detailed:* a real firewall adapter exists but is disabled, because automatic host blocking on
a demo laptop is unsafe.

**O4. "Show that Q-learning improves anything."**
*Short:* we cannot; it was not measured. *Medium:* we verified the mechanism, not the benefit. *Detailed:* a valid test
needs many real attacker sessions under randomised fixed versus learned personas; our lab has few sessions and a
synthetic warm start, so any claim would be unsupported.

**O5. "Why should anyone use this?"** As a teaching and research platform that shows how detection, explanation,
deception and response fit together safely, and as evidence of why benchmark accuracy must be checked on held-out
days.
