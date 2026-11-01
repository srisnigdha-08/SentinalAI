# SEC-001 — leaked honeypot key and account passwords: status and remediation checklist

First checked 2026-11-01 at `6883308`; re-checked 2026-11-02 (read-only). Values were compared by equality, bcrypt
or one-way hash and never printed. Checker: a scratch script (match flags only), not committed.

**Correction (2026-11-02):** the 2026-11-01 version said the affected accounts had 0 live sessions. The checker
queried a field that does not exist (`userId`; the schema field is `user`). Re-counted: `sentinel-db` holds **114
unrevoked, unexpired sessions** for the four affected accounts (table below). They are not usable as things stand
— see "Sessions" — but they are not revoked in the database either.

## State

| Question | Answer | Evidence |
|---|---|---|
| Which secrets leaked? | 1 honeypot ingest key, 3 verification-account passwords (shared by several accounts) | `scratch/run_browser_script.mjs` @ `315700c`, `scratch/run_all_verify.ps1` @ `a7fa029` |
| Repository public? | **Yes** (GitHub API 200 without credentials); both commits are fetchable on GitHub | status codes only |
| Old key configured or accepted anywhere? | **No** — no local env file and no file on the WSL honeypot host holds it; the backend refuses unknown keys | env scan, WSL hash scan, integration run |
| JWT secrets / SENTINEL_KEY leaked? | No | leaked files (values masked) |
| Backend exposure | binds `127.0.0.1` by default; compose publishes on loopback by default | static |

### Sessions (verified on the running system, 2026-11-02)

The 114 historical session rows' refresh tokens are not available (only their hashes are stored), so they cannot be
replayed directly. Instead the integration harness (`scripts/integration/run_integration.cjs`, run
`20261101_210037` UTC, real backend + MongoDB) puts a fresh session into exactly their state and exercises it:

| # | Requirement | Result |
|---|---|---|
| 1 | Old access tokens cannot authenticate | after a password change the earlier access token gets 401 on `/api/auth/me` |
| 2 | Old refresh tokens cannot be reused | a replayed (older-generation) refresh token gets 401 **and revokes that session** (`refresh-replay`); after a password change the earlier refresh token gets 401 |
| 3 | Password change increments `authVersion` | 0 → 1 |
| 4 | Pre-rotation sessions invalidated | all 4 sessions created before the change have `revokedAt` set (`password-change`); the 1 session issued by the change works |
| 5 | Logout-all revokes historical sessions | 0 open sessions afterwards; the other client gets 401 |
| 6 | Suspended accounts cannot authenticate | existing token 401, new login 403; reactivation restores login |
| 7 | Inactivity timeout | a session idle since 2026-10-18 (the state of the 114) gets 401 on both access and refresh and is revoked on the attempt (`inactivity-timeout`; default 900 s, not overridden in `backend/.env`) |

So the 114 rows are unusable today, and step 1 below revokes them in the database as well. After rotation, the
checker separates them from legitimate sessions by `createdAt` (before vs after the change) and `authVersion`.

## Account checklist

Status per account at 2026-11-02 (`leaked pw` = the leaked password still matches the stored hash).

| # | Database | Account | Role | Leaked pw | Unrevoked sessions (current authVersion) | Last login |
|---|---|---|---|---|---|---|
| 1 | sentinel-db | admin@sentinel.io | admin | **valid** | 75 (75) | 2026-10-18 |
| 2 | sentinel-db | arjun@sentinel.io | analyst | **valid** | 1 (1) | 2026-10-18 |
| 3 | sentinel-db | priya@sentinel.io | analyst | **valid** | 2 (2) | 2026-10-18 |
| 4 | sentinel-db | sara@sentinel.io | viewer | **valid** | 36 (36) | 2026-10-18 |
| 5 | sentinel-demo | admin@sentinel.io | admin | **valid** | 0 | 2026-10-18 |
| 6 | sentinel-demo | arjun@sentinel.io | analyst | **valid** | 0 | 2026-10-18 |
| 7 | sentinel-demo | priya@sentinel.io | analyst | **valid** | 0 | 2026-10-18 |
| 8 | sentinel-demo | sara@sentinel.io | viewer | **valid** | 0 | 2026-10-18 |
| 9 | sentinel-demo | pallavi@sentinel.io | analyst | **valid** | 0 | 2026-10-23 |

The other two `sentinel-db` accounts and three `sentinel-demo` accounts do not match any leaked password.

For **each** row, in this order (do `sentinel-db` first; it holds the sessions):

- [ ] **1. Change the password** as that user. Start the stack on the database (normal stack for `sentinel-db`;
      `scripts\demo\start-demo.ps1` for `sentinel-demo` — dashboard on http://localhost:3000), sign in, click
      **CHANGE PASSWORD** in the sidebar (added 2026-11-02; before that the screen only opened for forced changes),
      enter the current password and a new one from a password manager — a different one per account and per
      database. The server verifies the current password, bumps `authVersion` and revokes every other session.
- [ ] **2. Revoke explicitly** (optional; step 1 already revokes): "LOGOUT ALL SESSIONS" in the sidebar, or as an
      admin `POST /api/users/:id/force-logout`.
- [ ] **3. If the owner is not available:** an admin sets the account to `suspended` (`PUT /api/users/:id`
      `{ "status": "suspended" }`); verified: a suspended account can neither use an existing token nor sign in.
      There is no admin-side password reset in the API.
- [ ] **4. Reuse:** if the old password was used anywhere else (email, GitHub, Windows), change it there too.
- [ ] **5. Verify:** tell me, and I re-run the read-only checker: each row must show the leaked password "not valid"
      and 0 unrevoked sessions created before the change. Then try the old password once at the login screen: 401.

`scripts/demo/reset-demo-db.ps1` is **not** a shortcut: it clears demo activity but keeps users and sessions (the
2026-11-02 morning version of this file said otherwise; corrected).

Coordination: tell everyone who uses these accounts (teammates, the viva laptop) before step 1, because their
browser sessions end. Nothing else on the honeypot host or in the services needs to change: the key rotation is
already complete.

## Git history (needs your approval — destructive and shared)

The key is dead and step 1 kills the passwords, so a purge is hygiene, not the fix. If you want it:
`git filter-repo --replace-text` on a fresh mirror clone, force-push every branch that contains `315700c` /
`a7fa029` (`db-fixes`, `demo-readiness`, forks), have every collaborator re-clone (a rebase re-introduces the
commits), and ask GitHub Support to drop cached views and PR refs. GitHub serves commits by SHA until it garbage-collects them.

## Automated scanning (added 2026-11-02, hardened the same day)

`scripts/security/secret_scan.cjs` (no dependencies) prints commit, file, line, rule and the value's **length only**
(the first version printed two leading and two trailing characters; removed).

| Where | How | State |
|---|---|---|
| CI | job `secret-scan`: unit tests, tracked files, then **every commit of the push / PR** (`--range before..after`, or `--history` for a new branch) with `fetch-depth: 0` | catches a secret that a later commit deleted |
| Pre-commit (opt-in) | `git config core.hooksPath .githooks` → `.githooks/pre-commit` scans staged files | not enabled for anyone until they run that command |
| Audit | `--history` | 25 findings in history, all reviewed: the 3 SEC-001 passwords (still valid for the 9 account records above) plus values that open nothing (bcrypt-checked against all 22 accounts in 8 local databases; key values compared with every env file) |

`scripts/security/secret_scan_baseline.txt` lists those reviewed history findings (commit, file, rule; no values) so
CI judges new commits only; its header states that the SEC-001 entries are not rotated yet. Exceptions need a
reason: `secret-scan: allow (<reason>)` on the line (a bare marker no longer counts), or an exact path in
`secret_scan_allow.txt` (directories only with a trailing `/`). Fixed false negatives: env-style `*_KEY` names
(`SENTINEL_KEY`), credentials in any URI scheme, backup copies (`*.bak`, `*.bak-*`, `*.orig`), and real values
containing "test" inside a word. Tests: `scripts/security/secret_scan.test.cjs` (9, including a throwaway-repository
range scan and a check that no 4-character fragment of the value is printed).
