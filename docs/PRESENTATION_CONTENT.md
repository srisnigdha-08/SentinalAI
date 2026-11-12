# SentinelAI final presentation content

Slide-by-slide content for the final-year presentation (about 15–18 minutes plus a 15-minute live demo). Every number
is from [`PROJECT_METRICS.md`](PROJECT_METRICS.md); every screenshot is from the 2026-11-03 rehearsal on the real
system (`presentation/screenshots/`). Related work is described by category; add citations from your report's
literature review rather than from this file.

---

## 1. Title

**SentinelAI: An Adaptive Cyber-Defence Platform Combining Deception, Machine-Learning Detection and
Policy-Governed Response**

Name, register number, guide, department, date.

*Screenshot:* `presentation/screenshots/02-dashboard-analyst.png`

## 2. Problem statement

- Security teams face high alert volumes with little context about *why* an alert fired.
- Signature tools miss behaviour they have no rule for; many ML detectors are reported on optimistic random splits.
- Honeypots collect attacker behaviour but are usually static and disconnected from detection and response.
- Automated blocking is risky without policy checks, expiry and rollback.

*Speaker note:* "Our question was whether these pieces can work together in one auditable system, and how far an ML
detector trained on a public dataset really generalises."

## 3. Objectives

1. Capture and analyse attacker behaviour with a real SSH honeypot (MITRE ATT&CK mapping, engagement scoring).
2. Classify network flows with an explainable ML model; explain each alert from the data that produced it.
3. Adapt the honeypot persona with a reinforcement-learning recommender.
4. Respond through a policy-governed containment state machine with audit and rollback, safely simulated.
5. Evaluate honestly, including generalisation to unseen attack days.

## 4. Existing approaches and research gaps

| Approach (category) | Strength | Gap SentinelAI addresses |
|---|---|---|
| Signature IDS | precise for known attacks | no learning; no explanation of novel behaviour |
| ML IDS on benchmark datasets | high reported accuracy | often random-split evaluation; little per-alert explanation |
| Static honeypots | real attacker data | fixed persona; not linked to detection or response |
| SOAR / automated response | speed | risk of unsafe actions without policy, expiry, rollback |

*Speaker note:* "Our contribution is integration and honest evaluation, not a new algorithm."

## 5. Proposed architecture

```
Browser (React) ──REST + Socket.IO──► Backend (Express) ──► MongoDB
                                         │  ▲
                        service key ─────┘  └──── Cowrie log parser ◄── Cowrie SSH honeypot (WSL)
                                         ▼
                                AI engine (FastAPI, loopback)
                          XGBoost + Isolation Forest, SHAP, Q-learning
```

Points: every request goes through the backend; the engine is loopback-only; roles and redaction are enforced on the
server; real-time updates use per-role Socket.IO rooms.

## 6. Technologies

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Recharts, Socket.IO client |
| Backend | Node.js 24, Express, Socket.IO, Mongoose, JWT, CSRF |
| AI engine | Python 3.11, FastAPI, XGBoost, scikit-learn, SHAP |
| Data | MongoDB 7 |
| Deception | Cowrie SSH honeypot in WSL Ubuntu |
| Quality | Jest, pytest, Playwright, ESLint, GitHub Actions (7 jobs), secret scanner |

## 7. System modules

1. **Honeypot intelligence:** Cowrie sessions, commands, MITRE mapping, deception score.
2. **AI detection:** 53-feature schema validation, XGBoost classification, Isolation Forest anomaly signal, threat score.
3. **Explainability:** per-threat SHAP from the stored feature vector.
4. **Adaptive deception:** Q-learning persona recommender and rotator.
5. **Response:** containment policy, state machine, mock adapter, honeypot deny-list, audit, rollback.
6. **SOC dashboard:** live feed, threat logs, analytics, role-based views (admin, analyst, viewer).
7. **Investigation tools:** Attack Time Machine (replay a recorded honeypot session), AI Trust Meter (what limits a
   stored prediction, no trust percentage), Deception Arena (static vs adaptive persona under controlled conditions).

## 8. AI/ML architecture

- Input: 53 flow features (CICIDS2017-derived), validated; malformed → rejected; many defaults → never auto-blocked.
- XGBoost multi-class classifier (10 classes) + Isolation Forest trained on benign traffic.
- Threat score combines the classifier's attack probability with the anomaly signal.
- Thresholds: **0.90** → threat + alert; **0.92** → CRITICAL, auto-block if enabled.
- Integrity: SHA-256 model registry and a 20-row golden set reproduced at every start.

*Screenshot:* `presentation/screenshots/05-shap-explanation.png` — "the explanation is computed from the exact stored
feature vector, and refused if re-scoring does not reproduce the prediction."

## 9. Honeypot and reinforcement learning

- Real SSH sessions; commands mapped to ATT&CK (rehearsal: T1082, T1033, T1003.008, T1595).
- Reward: engagement (duration, commands, intent bonuses, IOCs, login) minus a fingerprinting penalty.
- Tabular Q-learning (α 0.1, γ 0.9, ε 0.2 → floor 0.05) over 5 Linux personas; one decision per served persona,
  applied by the rotator.
- **Honest limit:** the learner was warm-started from a synthetic table and its effect on real attacker engagement
  has **not** been measured.

*Screenshot:* `presentation/screenshots/06-honeypot-analytics.png`

## 10. Autonomous response mechanism

- Policy first: loopback, link-local, local services and configured targets are refused.
- State machine: REQUESTED → VALIDATING → APPROVED → APPLYING → ACTIVE → (EXPIRING / ROLLING_BACK) → ROLLED_BACK.
- One active action per target; TTL expiry; operator rollback; audit at every step.
- Enforcement: **mock adapter (simulated)**; the honeypot's deny-list is the only real enforcement.
- Engine down → flows stored as DEGRADED, never blocked.

*Screenshot:* `presentation/screenshots/09-settings-containment.png`

## 11. Implementation highlights

- Session security: in-memory access token, rotating refresh cookie, CSRF, socket re-authorisation, revocation that
  disconnects sockets.
- Viewer redaction on the server, for REST and Socket.IO.
- Live feed that reconnects after outages and catches up missed threats.
- Single-threaded inference per request: engine CPU about 60 % → 8 % of the machine.
- Demo isolation: separate demo database and Q-table; scripts to start, stop, reset and recover.

*Screenshot:* `presentation/screenshots/10-dashboard-viewer-redacted.png` (viewer sees `198.51.100.xxx`)

## 12. Experimental results

| Evaluation | Attack recall | Benign false-positive rate |
|---|---|---|
| Random 80/20 split (served model) | 99.8 % (95.2 % at the 0.90 line); accuracy 98.97 %, macro F1 0.874 | 0.36 % (0.23 % at the line) |
| Train Mon–Wed, test Thu–Fri | 50.6 % | 0.12 % |
| Leave one day out | 3.1–33.4 % | up to 4.1 % |
| Later held-out traffic at the 0.90 line | 78.6 % | 0.154 % |
| Six CSE-CIC-IDS2018 development days at the 0.90 line (diagnostic) | 15.2 % | 0.24 % |

Deception Arena (scripted and simulated attackers only): scripted runs give identical sessions under both strategies,
as they must; a 12-pair simulated run found no difference in commands per session (95 % CI −0.42 to 1.42). No
improvement for real attackers has been established.

Performance: single flow p95 ≈ 30 ms; explanation p95 48 ms; backend 75–98 requests/s at 20 clients with no errors.
Testing (2026-11-12): 1,657 backend, 959 engine, 139 frontend unit and 106 Chromium browser tests passing (plus 12
phone/tablet layout tests); 42 integration checks passed when last run on 2026-11-03.

*Speaker note:* "High random-split accuracy measures recognition of near-copies from the same capture. The day
held-out results are the honest estimate for unseen attacks, and they are poor. We report both."

## 13. Demonstration

Live: Demo A (honeypot → MITRE → persona rotation), Demo B (replayed flows → threats → SHAP), Demo C (auto-block →
simulated containment → honeypot refusal → rollback; engine outage). Script: [`DEMO_REHEARSAL_SCRIPT.md`](DEMO_REHEARSAL_SCRIPT.md).

Backup screenshots if the live demo fails: `02` dashboard, `04` threat logs, `05` SHAP, `06`/`07` honeypot, `08` AI
analytics, `09` settings and containment, `10` viewer redaction.

## 14. Limitations

- The model misses most attacks from days and tools it never saw (3–51 % recall); several classes have under 10
  test flows.
- Flows in the demo are recorded CICIDS2017 records replayed, not live capture.
- Host-firewall enforcement is simulated; the Windows Firewall adapter has never run live.
- The persona learner's benefit for real attackers is not established (Deception Arena: scripted and simulated only);
  its state is only the previous persona.
- The AI Trust Meter shows evidence and limitations, not the probability that a prediction is correct.
- Auto-block acts on a single flow (no correlation); single-host deployment; no TLS; Docker untested.
- Credentials once committed to history (SEC-001), risk accepted, not rotated.

## 15. Future improvements

- Train and validate on more diverse data, with day- and dataset-held-out evaluation as the acceptance test; run the
  pre-registered external test on the protected 2018 days once.
- Live flow capture (e.g. a flow exporter) instead of replay.
- A controlled study of persona rotation against a fixed persona; richer RL state.
- Multi-event correlation before automatic containment; a real enforcement adapter in an isolated lab.
- Deployment hardening: TLS termination, Docker validation, scheduled backups, secret rotation (SEC-001).

## 16. Conclusion

SentinelAI shows that deception, explainable ML detection and policy-governed response can be integrated into one
tested, auditable system with role-based security and real-time operation. Its central research finding is negative
but important: excellent in-distribution accuracy on CICIDS2017 does not carry over to unseen attack days or tools,
so random-split accuracy alone should not be used to claim intrusion-detection capability.
