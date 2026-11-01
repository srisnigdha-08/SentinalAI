# SEC-001 — leaked honeypot key and account passwords: status and remediation plan

Checked 2026-11-01 at `6883308`, read-only. Values were compared by equality or one-way hash; none was printed.
Checker: a scratch script (bcrypt compare against the stored hashes, match flags only); not committed.

## Current state

| Question | Answer | Evidence |
|---|---|---|
| Which secrets leaked? | 1 honeypot ingest key, 3 verification-account passwords | `scratch/run_browser_script.mjs` @ `315700c`, `scratch/run_all_verify.ps1` before `a4f606d` |
| Is the repository public? | **Yes** — `GET api.github.com/repos/srisnigdha-08/SentinalAI` → 200 without credentials | curl status code only |
| Are the leaking commits on GitHub? | **Yes**: `315700c` and `a7fa029` return 200 from the public commits API. Locally the key is in 3 commits reachable from `db-fixes`, `demo-readiness`, `origin/db-fixes`; the passwords are in 5 commits | `git log --all -S`, GitHub API status codes |
| Is the old key still configured anywhere? | **No.** `backend/.env`, `backend/.env.test`, `deployment/.env`, `.env.demo`, `.env.production`, `ai-engine/.env`: no match. The WSL honeypot host (`~/sentinelai-cowrie-test`, `/etc`, `~`, depth 4): no file holds it (sha256 compare). `/etc/sentinelai/honeypot.env` (the systemd unit's file) does not exist; the WSL lab reads the key from `backend/.env` at each start | env scan; WSL hash scan |
| Is the old key accepted? | **No** by construction: ingest compares against `HONEYPOT_API_KEY` only (`backend/utils/apiKeys.js`, constant-time), and no env holds the old value. A random key is refused with 401/403 on a live backend (integration run, check "old/unknown honeypot key is refused") | static + integration run |
| Do the leaked passwords still work? | **Yes.** `sentinel-db`: `admin@sentinel.io` (admin), `arjun@sentinel.io`, `priya@sentinel.io` (analysts), `sara@sentinel.io` (viewer). `sentinel-demo`: the same four plus `pallavi@sentinel.io` (analyst) | bcrypt compare |
| Live sessions for those accounts? | 0 in both databases (no unrevoked, unexpired AuthSession) | `authsessions` count |
| Exposure of the backend | binds `127.0.0.1` by default (`server.js`), compose now publishes on loopback by default — the passwords are usable by anyone who can reach a running backend, not from the internet by default | static |
| JWT secrets / SENTINEL_KEY leaked? | No: not present in the leaking files | leaked-file structure (values masked) |

## Remediation (needs your action or approval — nothing below has been done)

1. **Change the five account passwords now (you).** Sign in as each account and change its password (Settings →
   password, i.e. `PUT /api/auth/update-password`); for `sentinel-demo` do the same or recreate it with
   `scripts/demo/reset-demo-db.ps1`. There is no admin-side password reset: until an account's owner changes it, an
   admin can set its status to `suspended` (`PUT /api/users/:id`) and `POST /api/users/:id/force-logout`.
   `update-password` bumps `authVersion`, which revokes every existing session and refresh token for that user, so
   no separate revocation step is needed. If any of these passwords is
   reused on another service (email, GitHub), change it there too.
2. **Verify:** re-run the checker (ask me, or reuse its logic): every account must report "not valid".
3. **Key:** already rotated; nothing to do unless a second honeypot host exists that this check could not see
   (a cloud VM, a teammate's machine). Any such host must take the key from `backend/.env`, not a copy.
4. **History purge (optional, needs approval — destructive and shared):** the key is dead, so the purge only matters
   for the passwords, and step 1 makes them dead too. If you still want the history clean:
   `git filter-repo --replace-text` on a fresh mirror clone, force-push **every** branch that contains the commits
   (`db-fixes`, `demo-readiness`, and any fork), tell collaborators to re-clone (a rebase would re-introduce the
   commits), and ask GitHub Support to purge cached views/PR refs. GitHub keeps commits reachable by SHA until
   garbage collection, so rotation (steps 1 and 3) is the real fix; the purge is hygiene.
5. **Going forward:** keep `scratch/` scripts reading secrets from the environment only (`run_all_verify.ps1` already
   does); add a pre-commit secret scan (e.g. gitleaks) to the existing husky hook.
