# SEC-001 — credential rotation and session revocation runbook (owner-executed)

Status: **RESOLVED 2026-11-08** (bulk rotation by sec001_rotate.cjs, verified by the checker; see SEC001_REMEDIATION.md). Kept as a record of the procedure. No leaked value appears here
or in any output of the tools it uses. Background and history: `SEC001_REMEDIATION.md`.

## What must change

Three passwords leaked in public Git history (`315700c`, `a7fa029`) still unlocked these nine account records when
last checked (2026-11-02). The honeypot key that leaked with them is already rotated and refused.

| # | Database | Account | Role |
|---|---|---|---|
| 1 | sentinel-db | admin@sentinel.io | admin |
| 2 | sentinel-db | arjun@sentinel.io | analyst |
| 3 | sentinel-db | priya@sentinel.io | analyst |
| 4 | sentinel-db | sara@sentinel.io | viewer |
| 5 | sentinel-demo | admin@sentinel.io | admin |
| 6 | sentinel-demo | arjun@sentinel.io | analyst |
| 7 | sentinel-demo | priya@sentinel.io | analyst |
| 8 | sentinel-demo | sara@sentinel.io | viewer |
| 9 | sentinel-demo | pallavi@sentinel.io | analyst |

## 0. Before you start (5 min)

1. Tell everyone who uses these accounts; their sessions end in step 2.
2. Back up both databases (keeps a way back if something goes wrong):
   `mongodump --uri mongodb://127.0.0.1:27017 --db sentinel-db --out <backup-dir>` and the same for `sentinel-demo`.
3. Generate nine new passwords in a password manager: one per account **and per database** (row 1 and row 5
   must differ). Do not reuse any leaked password, or any password used elsewhere.
4. Baseline, read-only: `node scripts/security/sec001_check.cjs`. Expected now: exit code 1, the nine rows `OPEN`.

## 1. Rotate (per account, `sentinel-db` first)

Normal stack for `sentinel-db`; `scripts\demo\start-demo.ps1` for `sentinel-demo` (dashboard http://localhost:3000).

For each row: sign in as that user → sidebar **CHANGE PASSWORD** → current password, then the new one. The
server checks the current password, sets the new bcrypt hash, sets `passwordChangedAt`, increments `authVersion`
and revokes every other session of that account (verified by the integration harness, workflow D).

If a user cannot be reached: an admin sets the account to `suspended` (Users page or
`PUT /api/users/:id {"status":"suspended"}`); a suspended account can neither use a token nor sign in. Rotate
when they are back, then reactivate. There is no admin-side password reset.

## 2. Revoke (belt and braces)

Step 1 already revokes. For accounts that were suspended instead, or to be certain: admin
`POST /api/users/:id/force-logout` per account (increments `authVersion`; every session ends), or **LOGOUT ALL
SESSIONS** while signed in as the user.

## 3. Elsewhere

If any leaked password was also used on another service (email, GitHub, Windows, WSL), change it there.

## 4. Verify (read-only)

`node scripts/security/sec001_check.cjs` — prints, per account: whether a leaked password is still valid, when the
password was changed, and how many unrevoked, unexpired sessions predate that change. It reads only; it prints
the number of leaked candidates it compared, never a value or hash. Pass criteria, for **all nine** rows:

- `leaked password valid: no`
- `pre-change: 0`
- exit code `0`

Then try one old password once at the login screen: it must be refused (401).

## 5. Close SEC-001

Send the checker output (it contains no secrets). SEC-001 is set to RESOLVED in `FINDINGS.md` only with that
evidence. History rewrite stays optional and needs separate approval (`SEC001_REMEDIATION.md`, "Git history").
Until step 4 passes: keep the backend on loopback and do not copy either database to another machine.

## Checker details

`scripts/security/sec001_check.cjs`, tests `scripts/security/sec001_check.test.cjs` (synthetic accounts and values
on a disposable MongoDB: flags, exit codes, no value or hash in the output, no data changed). Options:
`--mongo <uri>`, `--db <name>` (repeatable). It was **not** run against your databases during preparation.
