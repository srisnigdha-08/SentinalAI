# Low-Priority Fixes Report (L1–L15)

Date: 2026-10-21 · Branch `db-fixes` · **Uncommitted.** Issue list: `docs/BACKEND_STUDY_GUIDE.md`, Phase 4 "Low".
Also includes the leftover from the medium round: the failing OBS-01 linking test is fixed.

## Leftover from the medium round
`backend/tests/threatSecurityRemediation.test.js` ("OBS-01 … Bi-directional Linking") still expected the
old two-step link (`pred.save()` after the threat write). It now asserts the M3 invariant instead: the
prediction is created with `generatedThreat` equal to the id the threat is created with, and no follow-up
save happens. 20/20 in that file pass.

## Fixes

| ID | Issue | What changed | Files | Verified by |
|---|---|---|---|---|
| L1 | Unused `exec` import in the collector | Removed (done in the medium round) | `honeypot/collectors/session_collector.js` | collector suites |
| L2 | `id` regex tagged almost anything as RECONNAISSANCE (`hidden`, `android`) | Whole-word `\b(uname\|id\|whoami\|ifconfig)\b` in both the backend collector and the Cowrie parser | collector, `honeypot/parsers/log_parser.py` | `ai-engine/tests/test_low_fixes.py` (6 cases), manual check of the JS version |
| L3 | Bare `except: pass` hid a corrupt Q-table | Logged warning on unreadable table (done in M5) | `ai-engine/rl_engine/deception_scorer.py` | `tests/test_medium_fixes.py` |
| L4 | `predict()` + `predict_proba()` ran the forest twice; `?explain=true` re-extracted features and predicted again | `_classify()` does one `predict_proba` pass and takes the argmax via `classes_`; SHAP reuses the vector and class column | `ai-engine/inference/predictor.py` | `tests/test_low_fixes.py` (1 forest pass with SHAP); live check with the real model |
| L5 | Login was faster for unknown emails (account enumeration by timing) | Unknown emails run one bcrypt compare (cost 12, same as stored hashes) against a fixed hash | `backend/controllers/authController.js` | `backend/tests/lowFixes.test.js` |
| L6 | Duplicate, unused deception scorer | Deleted | `honeypot/rl_engine/deception_scorer.py` | nothing imported it |
| L7 | 18 tracked `*.bak-*` / `*.orig-*` code backups | Removed with `git rm`; `.gitignore` ignores those patterns. Git history keeps them; the rollback notes in `ai-engine/experiments/gate1_phase3d_*` that name them now refer to history | repo-wide | `git status` |
| L8 | `JWT_EXPIRES_IN` / `JWT_REFRESH_EXPIRES_IN` documented but unused | Removed from both env examples, with a note that access tokens are 15 min and sessions are server-side | `backend/.env.example`, `deployment/.env.demo.example` | grep: only test files still set them (harmless) |
| L9 | Blocker defaulted to `http://backend:5000`; output plugin present but disabled without explanation | Blocker and sniffer default to `http://localhost:5000/api` like the parser; README has a config table, says why `sentinel_output.py` stays disabled (double ingestion), and corrects the key the parser uses (`HONEYPOT_API_KEY`) | `honeypot/cowrie/sentinel_blocker.py`, `honeypot/sniffer/sniffer.py`, `honeypot/README.md` | review |
| L10 | Alerts silently deleted after 7 days by TTL | `ALERT_RETENTION_DAYS` (1–365, default 7) sets the default `expiresAt`; documented | `backend/models/Alert.js`, `backend/.env.example` | `backend/tests/lowFixes.test.js` |
| L11 | Pydantic v1 `class Config` (deprecation warnings) | `model_config = ConfigDict(...)` on `Record` and `SessionData` | `ai-engine/inference/main.py` | pytest warnings |
| L12 | Root `models/` duplicate and unused candidate models | **Not deleted**: `docs/PRESERVED_ASSETS_SHA256.json` lists them as preserved assets. Added `models/README.md` marking the folder as an inactive archive (with the hash/metric differences); the model registry (M11) already ensures no other `.pkl` is loaded | `models/README.md` | registry tests |
| L13 | Hard-coded path in the launcher | `Set-Location (Join-Path $PSScriptRoot "backend")` | `start-backend.ps1` | review |
| L14 | Mongo pool size and timeout hard-coded | `MONGO_MAX_POOL_SIZE` (10), `MONGO_SERVER_SELECTION_TIMEOUT_MS` (5000), documented | `backend/config/db.js`, `backend/.env.example` | backend suites |
| L15 | Seed Q-table provenance unknown | Documented what can be established (saved 2026-10-05, 12,087 episodes, first committed `5ea7051`) and that no script regenerates it — treat it as demo state. Not regenerated: its hash is pinned by `tests/test_q_table_safety.py` (`BASELINE_HASH`) and it is a preserved asset | `ai-engine/README.md` | — |

Housekeeping in the same pass: Prettier and ESLint `--fix` on every backend `.js` file changed in this
working tree (formatting only), and the dead `BlockedIP` require removed from `aiService.storePrediction`.
ESLint on those files: **0 errors**; 8 warnings remain, all unused variables/parameters that predate this work.

## Test results

Full runs after all low fixes (and the medium + high work in the same tree):

| Suite | Result |
|---|---|
| Backend Jest (`npx jest --runInBand --ci`) | **61 suites passed, 4 skipped; 992 passed, 13 skipped, 0 failed** |
| AI engine pytest (`.venv`, Python 3.11.9) | **379 passed, 0 failed** (warnings 8 → 6: the Pydantic `class Config` deprecations are gone) |
| Frontend `npm test` | **36 passed, 0 failed** |
| Frontend `npm run build` | **built** |

The 4 skipped backend suites need a real MongoDB (`AUTH_TEST_MONGO_URI`), as before.
New tests: `backend/tests/lowFixes.test.js` (3), `ai-engine/tests/test_low_fixes.py` (7).

## Not changed on purpose
- Root `models/`, the two `xgb_*.pkl.bak` files and `ai-engine/models/q_table.json` are listed as preserved
  assets; deleting or rewriting them would break the project's own asset-integrity checks.
- `sentinel_output.py` stays disabled; enabling it alongside the parser would double-ingest every event.
- The C3 follow-up (raising the alert line to ≈ 0.85 after validation-split confirmation) is still open.
