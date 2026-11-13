# Demo start-up and troubleshooting

How to start the Windows demo stack, check that each service really works, and recognise the usual failures.
Verified on 2026-11-13 against `main` at `2fe52b9` plus the fixes in this change.

## The URLs (read this first)

| What | URL | Notes |
|---|---|---|
| **Dashboard** | **http://localhost:3000** | The only URL to open in a browser. Vite proxies `/api` and `/socket.io` to the backend. |
| Backend API | `http://<WSL gateway>:5000`, e.g. `http://172.29.32.1:5000` | Printed by `start-demo.ps1`. The address changes after a reboot. |
| AI engine | http://127.0.0.1:8000 | Loopback only. |
| `http://localhost:5000` | **refused** (`ERR_CONNECTION_REFUSED`) | Expected, not a failure. See below. |

The demo backend listens **only** on the Windows host address that WSL sees (the WSL gateway), so the Cowrie
blocker and the deception rotator inside WSL can reach it. Nothing listens on `127.0.0.1:5000`, so a browser, `curl`
or `Test-NetConnection 127.0.0.1 -Port 5000` is refused even while the backend is healthy. The backend's start-up
line says so: `SentinelAI Backend ready on port 5000 (listening on http://172.29.32.1:5000 only)`.

Running `node server.js` by hand without `HOST` still binds `127.0.0.1:5000` (the README's local-development path).

## Start, check, restart, stop

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\start-demo.ps1      # engine, backend, frontend, Cowrie parser
powershell -ExecutionPolicy Bypass -File scripts\demo\status-demo.ps1     # read-only: what answers, and why not
powershell -ExecutionPolicy Bypass -File scripts\demo\restart-backend.ps1 # after a git pull with backend changes
powershell -ExecutionPolicy Bypass -File scripts\demo\stop-demo.ps1       # closes the demo windows
```

`start-demo.ps1`:
- refuses to start while demo windows from an earlier start are still open (no duplicate instances), and while
  anything listens on 8000, 5000 or 3000 (it names the process and its start time);
- waits up to 120 s (`-TimeoutSec`) for real readiness: the engine's `/ready`, the backend's `/health/live` and
  `/health/ready`, and the frontend;
- prints `READY` / `DEGRADED` with the backend's dependencies (database, AI engine, revocation);
- when the backend does not answer, says whether `node` exited (read the `[Startup]` error in its window) or is
  running but unreachable, and who holds port 5000;
- exits with code 1 when any check failed; the windows stay open so their errors can be read.

`-DemoDb`, `-StateDir` and `-NoParser` exist for rehearsals. A non-default database or state folder is refused while
Cowrie or the rotator run in WSL, because they poll whatever answers on the WSL gateway address: a rehearsal backend
would hand Cowrie its own (empty) deny-list and the rotator its own persona decisions.

## Checking each service by hand

| Service | Check | Healthy answer |
|---|---|---|
| MongoDB | `Get-Service MongoDB` | `Running` |
| AI engine | `Invoke-RestMethod http://127.0.0.1:8000/ready` | `status: ok` |
| Backend alive | `Invoke-RestMethod http://<gateway>:5000/health/live` | `status: alive` |
| Backend ready | `Invoke-RestMethod http://<gateway>:5000/health/ready` | `ready` (or `degraded` = AI engine down, still safe) |
| Backend routes | `http://<gateway>:5000/api/reports/security-summary` without a token | `401` (a `404` means the backend predates a pull) |
| Frontend | http://localhost:3000 | the login page |

`/health` (no suffix) is strict: it answers **503 whenever the AI engine is unavailable**, even though the backend is
running. Earlier versions of the scripts used it and reported a running backend as `NOT RESPONDING`.

If the backend starts before the engine has loaded its models, `/health/ready` shows `AI engine unavailable` for up to
30 s (the engine circuit breaker's reset time) and then recovers by itself.

## Recognising a backend start-up failure

All start-up failures are logged with a `[Startup]` prefix in the backend window and in `backend/logs/sentinel*.log`,
and the process exits with code 1:

| Message | Meaning | Fix |
|---|---|---|
| `Cannot listen on <ip>:5000: the port is already in use` | another backend (demo window, test server) holds the port | `status-demo.ps1` names it; `stop-demo.ps1` |
| `Cannot listen on <ip>:5000: this machine has no such address` | `HOST` is not an address of this machine (the WSL address changed after a reboot) | start the demo again |
| `MongoDB connection failed (MongooseServerSelectionError)` | MongoDB not running | `Start-Service MongoDB` |
| `Backend failed to start: …` | anything else after the database connected | read the message |

A backend that disappears **without** any log line was terminated from outside (its window closed, or
`stop-demo.ps1`, which force-closes the demo windows). A crash always logs `[Shutdown] Uncaught exception`.

## Correlated auto-block (default)

`AUTO_BLOCK_POLICY` is unset in `backend/.env`, so the correlated policy applies. With auto-block switched on
(Settings), a network-flow threat at the block line requests containment only when, from one source within 300 s,
there are at least 3 suspicious flows (at or above the alert line) and at least 2 at the block line. Otherwise the
threat is recorded as `NEEDS_APPROVAL` with the reason. Trusted (`CONTAINMENT_TRUSTED_IPS`) and protected addresses
(loopback, link-local, `CONTAINMENT_PROTECTED_TARGETS`) are `SUPPRESSED_TRUSTED`; an address already deny-listed or
requested within 600 s is `SUPPRESSED_DUPLICATE`. Containment uses the mock adapter (the Cowrie deny-list; no host
firewall rule). Details: [CONTAINMENT_ENFORCEMENT.md](CONTAINMENT_ENFORCEMENT.md).

Demo C's harness (`scripts/integration/run_integration.cjs`) pins `AUTO_BLOCK_POLICY=single_flow`; it does not
exercise the default. `backend/tests/correlatedAutoBlockIntegration.test.js` does, end to end.

Honeypot sessions are a separate path: a scored Cowrie session at the block line is contained on its own (subject to
`HONEYPOT_AUTOBLOCK_MODE` and the hourly cap), because the attacker interacted with the honeypot.

## What is enabled, disabled, simulated or blocked

As reported by the Capability Status page (`GET /api/system/capabilities`) on a default demo start:

| Capability | Label | What it means |
|---|---|---|
| Correlated auto-block | implemented and tested | default policy above |
| Cowrie deny-list | implemented and tested | the honeypot refuses deny-listed sources (honeypot only, not the host) |
| Host firewall (Windows Firewall / iptables) | implemented, not enabled | containment is simulated (mock adapter) |
| Network capture | implemented, not enabled | no capture service runs; analyst-submitted flows are labelled `manual` |
| Q-learning evidence | experimental | seed episodes are a synthetic warm start; session evidence is tracked by source |
| Persona policy v2 | shadow only, **NOT READY** | recorded next to v1, never applied |
| Deception Arena | simulated | results describe the simulator, not real attackers |
| Session ML | blocked | pipeline exists; no classifier trained (too few independent labels) |
| Windows persona (`windows_srv`) | not implemented | refused everywhere (Cowrie emulates a Linux shell) |
| ML generalisation | experimental | deployed `xgb_cicids_v1` unchanged |

None of these is production-ready because a page renders; the labels above are the evidence-backed status.
