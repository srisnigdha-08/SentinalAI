# Performance and resilience (measured 2026-11-03, batch 13)

How SentinelAI behaves under local demonstration load and when individual components fail.
- **Measured** means run on this machine: Windows 11, 16 logical cores, local services.
- Anything else is labelled an expectation or a recommendation.
- Nothing here was run with Docker, nginx/TLS or a real firewall.

## 1. How to reproduce

| What | Command (repository root) | Touches |
|---|---|---|
| Engine latency and concurrency | `ai-engine\.venv\Scripts\python scripts\perf\engine_latency.py --concurrency 1,5,10,20 --per-client 40` | its own engine on 127.0.0.1:18300, throwaway key and Q-table |
| Model threading, in process | `ai-engine\.venv\Scripts\python scripts\perf\njobs_breakdown.py` | reads `models/` only |
| End-to-end load and failure recovery | `node scripts/perf/load_resilience.cjs --per-client 10` | its own throwaway `mongod` (127.0.0.1:27419, temp dir, deleted afterwards), engine :18200, backend :15200, fault proxy :18201 |
| Query time versus collection size | `node scripts/perf/db_query_scale.cjs --sizes 1000,10000,50000` | its own throwaway `mongod` (127.0.0.1:27420, deleted afterwards) |
| Browser view timings and runtime errors | `cd frontend; npx playwright test e2e/page-performance.spec.js` | the E2E test database |

None of these reads `backend/.env` or touches `sentinel-db`, `sentinel-demo` or the MongoDB service. Containment
stays on the mock adapter. Evidence goes to `scripts/perf/runs/<time>/` (git-ignored).

## 2. AI engine

### Root cause found and fixed (PERF-001)

The served models were saved with `n_jobs=-1`. Every **single-flow** request therefore started an all-core
XGBoost/OpenMP team and an all-core Isolation Forest pool.
- For one row, that coordination costs more than the trees: full predict p50 was 5.0 ms in process with all
  cores, against 2.8 ms with one thread.
- Under concurrent requests the pools fought over the CPU. Throughput stayed flat at about 70 requests/s from 1
  to 20 clients, while the engine burned about half the machine.

The engine now runs each model call single-threaded:
- `SentinelPredictor._set_inference_threads`, applied in memory before the golden-set check.
- Model files and registry hashes are unchanged, and predictions are bit-identical (golden check;
  `tests/test_inference_threads.py`).
- `INFERENCE_N_JOBS=-1` restores the old behaviour.

### Concurrency (HTTP `/predict/internal`, golden vectors; before → after; zero errors and timeouts in every run)

| Clients | Requests/s | p50 ms | p95 ms | p99 ms | Engine CPU (% of machine) |
|---|---|---|---|---|---|
| 1 | 77 → 48 | 12 → 16 | 13 → 32 | 26 → 34 | 56 → ≈ 0 |
| 5 | 75 → 127 | 65 → 39 | 85 → 63 | 91 → 72 | 56 → 7 |
| 10 | 70 → 118 | 142 → 85 | 165 → 115 | 181 → 122 | 50 → 7 |
| 20 | 68 → 132 | 281 → 147 | 339 → 204 | 607 → 230 | 50 → 7 |

On-demand explanations (`/explain/vector`) improved similarly: 20 clients p99 594 → 234 ms; 1 client p95 60 → 37 ms.

**Reproduction on a busier machine (2026-11-03, two back-to-back pairs in opposite order).** Background apps used
about 20–35 % CPU and left 0.7–0.9 GB of 7.7 GB memory free. `INFERENCE_N_JOBS=-1` reproduces the old behaviour.

| `/predict/internal` | Requests/s (old → new) | p95 ms (old → new) | p99 ms (old → new) | CPU % of machine (old → new) |
|---|---|---|---|---|
| 1 client | 68–75 → 40 | 19–20 → 33–35 | 29–35 → 35–36 | 58–73 → 3 |
| 5 clients | 67–76 → 86–105 | 81–94 → 74–80 | 87–99 → 85–88 | 51–61 → 7 |
| 10 clients | 74–76 → 90–110 | 153–154 → 133–150 | 167–169 → 165 | 60 → 7 |
| 20 clients | 71–74 → 70–86 | 301–312 → 293–492 | 370–543 → 463–573 | 58–60 → 8 |

`/explain/vector` showed no throughput change (about 75–80 requests/s either way) at the same CPU reduction.

What holds in every run: the engine uses about **one eighth of the CPU** (≈ 60 % → ≈ 8 % of the machine) with
identical predictions, explanations and zero errors. The throughput gain depends on how busy the machine is: about
2× on the quieter run, +15–45 % at 5–10 clients on the busy one, and none at 20 clients there, where tail latency
was not better. One idle client pays about +15 ms p95, still inside the 50 ms target. The setting is kept because a
demo laptop also runs the backend, MongoDB, the browser and Cowrie, which the old all-core pools starved; the
headline 2× figure is not claimed as reproducible.

**Single client, sequential (300 requests, measured back to back):**

| | Predict p50 / p95 | With SHAP, p95 | Explain p95 |
|---|---|---|---|
| New (`n_jobs=1`) | 15.8 / 30.3 ms | 34.8 ms | 40.3 ms |
| Old (`n_jobs=-1`) | 10.5 / 33.1 ms | 46.0 ms | 41.1 ms |

The trade-off is a few milliseconds at p50 for one idle client. The model computation is faster, and the new p50
sits on Windows' ~15.6 ms timer tick: the old pools' spinning threads kept a CPU awake, which shortened the hand-off
back to the event loop. All tail latencies are equal or better and inside the 50 ms target.

**Startup and memory:** ready in 4.6–6.1 s (before 3.8–6.9 s, varies run to run); about 250–270 MB resident.

## 3. Backend end to end (`load_resilience.cjs`; real CICIDS2017 flows through `/api/ai/analyze`)

| Clients × requests | Responses | Requests/s | p50 / p95 / p99 ms |
|---|---|---|---|
| 1 × 10 | 10/10 OK | 39–47 | 19–24 / 36–50 / 36–50 |
| 5 × 10 | 50/50 OK | 66–98 | 44–77 / 89–107 / 100–124 |
| 10 × 10 | 100/100 OK | 74–94 | 102–129 / 151–196 / 171–218 |
| 20 × 10 | 200/200 OK | 82–98 | 200–234 / 269–331 / 313–399 |

Ranges cover two runs. Each request includes login-protected routing, inference, MongoDB writes, alerting and socket
fan-out.

**Consistency:**
- 360 predictions were stored for 360 requests.
- 121 threats were created for the 121 qualifying predictions, each linked to exactly one prediction, with
  0 duplicates.
- Admin, analyst and viewer sockets each received all 121 `new_threat` events with 0 duplicates. Viewers received
  only redacted IPs, and privileged roles never did.

**Database scale** (median of 7, real `threatService`):

| Threats | List, page 1 | Filtered | Text search | Dashboard analytics |
|---|---|---|---|---|
| 1,000 | 3.9 ms | 3.5 ms | 6.5 ms | 7.1 ms |
| 10,000 | 4.5 ms | 3.3 ms | 16.1 ms | 25 ms |
| 50,000 | 12 ms | 5.5 ms | 58 ms | 112 ms |

- The list query uses the `createdAt` index.
- Text search (case-insensitive regex) and dashboard analytics (whole-collection aggregations, polled every 30 s per
  open dashboard) grow linearly. That's acceptable at demo scale (hundreds of threats).
- Expectation: about 1 s per analytics call at about 500k threats.
- Recommendation if that scale is ever needed: pre-aggregated counters or a time-windowed `$match`.

## 4. Failure behaviour (all measured, `load_resilience.cjs` 15/15)

| Failure | Behaviour | Recovery |
|---|---|---|
| Engine slow (3 s) | request waits, scored normally | — |
| Engine slower than the backend's 10 s timeout | after 10.0 s the flow is stored as `DEGRADED` (MEDIUM, never blocked) | automatic |
| Engine unreachable | 4 attempts with retry (0.4–0.9 s each), then the **circuit opens** and later requests degrade in about 10 ms; `/health` returns 503; one "AI Engine" health alert | the circuit half-opens after `AI_CIRCUIT_RESET_MS` (30 s default) and the first success closes it; no backend restart needed |
| Explanation with the engine down | 503 `ENGINE_UNAVAILABLE` in 8 ms; the panel offers TRY AGAIN | works again once the engine is back |
| MongoDB down | API requests answer 503 after about 5 s (server-selection timeout), never hang; `/health` returns 503 | the backend reconnects by itself; served data again 1.1 s after `mongod` returned |
| MongoDB down → sockets | the 15 s session re-check fails closed and the server disconnects every socket (deliberate); while the database stays down, reconnect handshakes are refused with "Authentication service unavailable" | **fixed (WS-001):** clients retry with backoff (2, 4, 8, 16, then every 30 s, ±25 %) until the database is back, then rejoin their rooms; all three roles received threats again after an outage held 8 s past the disconnects |
| Session revoked or token expired | the server disconnects the socket; the retry handshake is refused with "Authentication rejected" | not retried: the dashboard refreshes the session or signs out; a logged-out session received no further events (harness) and signing out while a retry is pending opens no connection (E2E) |
| Backend restart | sockets reconnect and keep receiving events | integration harness D |
| Expired or invalid session | 401; sockets with a bad token rejected | integration harness D |
| Containment adapter failure | compensation restores the deny-list and ThreatLog state; a failed rollback is retried by reconciliation | unit tests (containmentPolicy 15–18, reconciliation) |
| Cowrie or parser disconnected | no new honeypot sessions; nothing else is affected; sessions left open are closed by the sweep (runs every 15 min, closes sessions idle for 6 h) | restart Cowrie and the parser (runbook §1) |

## 5. Browser (Playwright, Vite dev server; sidebar navigation; 3 runs each)

| View ready | Chromium | Firefox | WebKit |
|---|---|---|---|
| Threat Logs (first open; includes compiling the module) | 350–1,347 ms | 623–1,716 ms | 1,424–2,898 ms |
| Honeypot Analytics | 102–123 ms | 309–355 ms | 604–836 ms |
| AI Analytics | 125–135 ms | 375–510 ms | 697–1,131 ms |
| Dashboard | 174–239 ms | 605–719 ms | 719–990 ms |
| Explanation modal with chart | 126–138 ms | 170–289 ms | 298–717 ms |

No uncaught JavaScript errors occurred in the measured views. Expectation: the production build (`npm run build`) is
faster, since modules are bundled; it was not timed here.

## 6. Restart and recovery

- **Engine:** restart its window. The backend notices on its own; nothing else needs restarting.
- **MongoDB:** `Start-Service MongoDB`. The backend reconnects within seconds, and dashboards reconnect their live
  feed by themselves (WS-001).
- **Backend:** restart its window. Open dashboards reconnect.
- **Everything:** `scripts\demo\stop-demo.ps1`, then `scripts\demo\start-demo.ps1`, then
  `bash scripts/demo/cowrie-demo-mode.sh restart` in WSL.

## 7. Remaining limitations

- Measured on one Windows laptop with local services. No multi-host, container, TLS or production-scale tests.
- The engine is one uvicorn process. Throughput tops out at about 120–130 requests/s, and more workers would
  multiply memory (about 250 MB each). That's sufficient for demos, not for a production network tap.
- Dashboard analytics and text search scale linearly with stored threats (§3).
- Browser timings come from the dev server, not the production build.
