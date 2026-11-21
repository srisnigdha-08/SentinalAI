# Containment: correlation and enforcement

## Correlation (automatic containment decisions)

`services/containmentCorrelationService.js` decides whether a threat at the block line may request containment.
The default policy is `AUTO_BLOCK_POLICY=correlated`.

| Decision | When |
|---|---|
| `AUTO_BLOCK` | ≥ `CORRELATION_MIN_FLOWS` (3) suspicious flows (threats at or above the alert line) from the source within `CORRELATION_WINDOW_SECONDS` (300), and ≥ `CORRELATION_MIN_BLOCK_LINE_FLOWS` (2) of them at the block line |
| `NEEDS_APPROVAL` | at the block line without that evidence: the threat waits for an analyst, who approves with the existing manual block |
| `SUPPRESSED_TRUSTED` | protected target (loopback, link-local, `CONTAINMENT_PROTECTED_TARGETS`) or `CONTAINMENT_TRUSTED_IPS` (IPs/CIDRs: gateways, infrastructure) |
| `SUPPRESSED_DUPLICATE` | already on the deny-list, or a non-failed request within `CORRELATION_COOLDOWN_SECONDS` (600) |
| `MONITOR` / `DISABLED` | below the block line / auto-block off |

How it behaves:
- **Floors:** thresholds have safe minimums (at least 2 flows), so a misconfiguration cannot restore single-flow blocking.
- **Failures:** a failure fails closed and becomes `NEEDS_APPROVAL`.
- **Audit:** every decision is stored on the threat as `containmentDecision {decision, policy, reasons, evidence}`
  (flows, block-line flows, attack types, first and last seen) and shown in triage.
- **Scope:** containment records still go through the unchanged state machine (TTL, rollback, reconciliation).

`AUTO_BLOCK_POLICY=single_flow` restores the original behaviour, with simulated enforcement only. A real adapter
always forces `correlated`.

**Scope: single host.** The window is evaluated on this backend's own database. No multi-node correlation exists.

Tests (`tests/containmentCorrelation.test.js`):
- a single flow is held for approval
- correlated flows request containment
- the window boundary and analyst-marked false positives
- benign repeats below the alert line
- 25 distributed sources with one flow each, none auto-blocked
- 800 flows from one source, with a bounded query
- configurable thresholds and safe floors
- trusted CIDRs, cooldown and duplicates
- fail-closed behaviour
- end to end through `storePrediction`

`tests/correlatedAutoBlockIntegration.test.js` runs the **shipped default** (no `AUTO_BLOCK_POLICY`) end to end with
nothing stubbed but the adapter: `storePrediction` -> correlation -> `executeAutoBlock` -> `requestContainment` ->
mock adapter. It covers one flow held for approval, the third correlated flow producing exactly one ACTIVE mock
containment and one deny-list entry, duplicates after the block, concurrent flows, the cooldown before and after it
expires, trusted CIDRs and loopback, flows below the block line, and a rule that fails post-apply verification
(removed, recorded FAILED, no cooldown started). Demo C's harness pins `single_flow` and is not evidence for the default.

**Concurrent flows.** Several flows from one source can pass correlation before any of them writes the deny-list. The
deny-list write is insert-only (`$setOnInsert`): the request that created the entry enforces and alerts; the others
link to it, record `SUPPRESSED_DUPLICATE` ("added to the deny-list by a concurrent request"), and send no second
containment request or alert. An existing entry keeps its original reason and threat.

**Honeypot sessions are a separate path.** Correlation applies to network-flow threats (`storePrediction`). A scored
Cowrie session that updates an existing threat is contained on its own, gated by `HONEYPOT_AUTOBLOCK_MODE` and the
hourly cap, because the source interacted with the honeypot.

**Before enabling a real adapter:** `/api/honeypot/ingest/flow` and `/capture-heartbeat` accept the honeypot key
(the same key Cowrie uses, limited by source address). A holder of that key can submit crafted flows, labelled
`live_passive`, that reach correlation; correlation raises the bar from one flow to three but does not authenticate
them. With mock containment this can only add a Cowrie deny-list entry. Give the capture service its own key, or
require approval for flow-originated blocks, before real host-firewall enforcement is switched on.

## Enforcement

### What the dashboard says, and why

| Capability Status entry | Label | Meaning |
|---|---|---|
| Host-firewall adapters (Windows Firewall, Linux iptables) | **Implemented and verified** | The adapter code and its safety logic are verified with **mocked command execution only** (list below) |
| Real host-firewall enforcement | **Implemented, not enabled** | No real firewall rule is created. Actual host-firewall rules have **never** been created or tested by this project |
| Default containment (mock adapter) | **Implemented and tested — simulated** | The default. Every containment runs through the full lifecycle and audit trail, and no host firewall changes |
| Honeypot deny-list enforcement | Implemented and tested | Separate capability: Cowrie refuses deny-listed sources (the honeypot only, not the host) |

Passing mocked tests never upgrades the real-enforcement entry. If a real adapter were ever active, that entry would
show **Experimental**, not verified, until a real rule had been verified on a lab host.

### Architecture

```
POST /api/containment/actions (JWT; admin or analyst)      /api/threats/block-ip, correlated auto-block, ...
            \                                                         /
             containmentService.requestContainment
               REQUESTED -> VALIDATING (policy + per-target lock) -> APPROVED -> APPLYING
               adapter.applyRule -> [real adapters] verifyRule -> ACTIVE   | otherwise FAILED (+ cleanup)
             rollbackContainment / TTL reconciliation
               ACTIVE -> ROLLING_BACK -> removeRule -> [real adapters] inspectRule -> ROLLED_BACK | ROLLBACK_FAILED
```

- **Adapter choice:** `services/containment/adapterFactory.js` picks the adapter once. It is
  `MockContainmentAdapter` unless every real-enforcement gate passes.
- **Policy before any command:** the policy (`containmentPolicyService`) runs before any adapter call. It checks the
  requester (authenticated, active, no pending password change, admin or analyst; CIDR and permanent blocks need an
  admin), the target (a valid IP or CIDR, not too broad) and protected addresses (loopback, gateway, protected
  ranges, core ports).
- **Rejection:** a rejected request ends `REJECTED` and never reaches the adapter.
- **Duplicates:** an `ACTIVE` action for the same target is returned instead of a new one. A unique per-target lock
  makes concurrent duplicates collapse into one action, and `idempotencyKey` replays the first answer.
- **No internal shortcut:** the internal honeypot key is not a containment credential (`/api/containment/*` needs a
  user JWT). Internal routes reach containment only through the existing correlated auto-block policy.

| Adapter | What it is | State |
|---|---|---|
| `MockContainmentAdapter` | records a rule in memory, changes nothing | **default** |
| `WindowsFirewallAdapter` | `netsh advfirewall firewall add/show/delete rule`, inbound block from the target | implemented, **not enabled** |
| `LinuxIptablesAdapter` | `iptables` / `ip6tables -w -C/-I/-D INPUT -s <target> -m comment --comment SentinelAI-Rule-<id> -j DROP`, optionally through `wsl -d Ubuntu -- sudo -n` | implemented, **not enabled** |
| Unavailable | a real backend was requested but the gate refused it | falls back to the mock |

### Safety gates (unchanged)

Real enforcement needs **all** of these:
1. `CONTAINMENT_BACKEND=windows-firewall` or `linux-iptables` (exact spelling)
2. that backend's flag: `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true` or `ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT=true`
3. `CONTAINMENT_REAL_ENFORCEMENT_CONFIRM=I-AUTHORIZE-FIREWALL-CHANGES-ON-<hostname>`. This is bound to the machine
   (exact, case-sensitive), so a copied `.env` does not switch enforcement on elsewhere.
4. not a test run (`NODE_ENV=test` or a Jest worker) and not `CONTAINMENT_DRY_RUN=true`
5. `CONTAINMENT_PROTECTED_TARGETS` set, and `HONEYPOT_AUTOBLOCK_MODE=approve` (startup refuses otherwise)

Anything less gives the mock adapter.

The real adapters check the gate again on every call: they refuse with `FIREWALL_ENFORCEMENT_DISABLED` unless they
were constructed enabled and `NODE_ENV` is not `test` and `CONTAINMENT_DRY_RUN` is not `true`.

`GET /api/containment/status` reports `realEnforcementEnabled: true` only when a real adapter is the one in use.
It used to echo the Windows enable flag, which could read "enabled" while the mock was active.

### How command execution is protected

- **No shell.** `execFile` with an argument array, never a shell string. The target and the rule name are each one
  array element, so no metacharacter can start another command.
- **Allowlisted executables.**
  - Windows runs `%SystemRoot%\System32\netsh.exe` by absolute path. A bare `netsh` could be resolved from the
    current directory on Windows. `SystemRoot` is used only when it is a plain drive path; otherwise
    `C:\Windows` is used.
  - Linux starts only `iptables`, `ip6tables`, `wsl` or `sudo`. On Windows, `wsl` is also taken from System32.
  - `CONTAINMENT_LINUX_COMMAND_PREFIX` must be a JSON array of simple words that starts with `wsl` or `sudo`.
- **Strict inputs.**
  - Targets must be real IPv4/IPv6 addresses or CIDRs with a valid prefix.
  - Rule names must be `SentinelAI-Rule-<1-64 of [A-Za-z0-9-]>` (Windows also allows `_`).
  - The containment ID is stripped to `[A-Za-z0-9-]` before it is used.
  - Only SentinelAI-tagged rules are ever checked or removed.

### Verification after apply, cleanup and rollback

- **Post-apply verification.** Real adapters declare `requiresPostApplyVerification`, so after a reported success
  the rule is looked up again:
  - Linux: `iptables -C` must find the exact rule.
  - Windows: the rule must exist and, where netsh prints them, be `Enabled: Yes`, `Direction: In`,
    `Action: Block`, and list the target in `RemoteIP`.
  - An unconfirmed rule fails the action with `ENFORCEMENT_NOT_VERIFIED`. It is never `ACTIVE`.
- **Cleanup after a failed or unverified apply.** When a command ran but failed (for example, a timeout after the
  rule was created), or the rule was not verified, the service looks the rule up with the read-only, tri-state
  `inspectRule`, removes it if it is or may be present, and looks again. The outcome goes into the audit event
  (`FAILED_APPLY_CLEANUP` / `FAILED_APPLY_CLEANUP_UNCONFIRMED`) and into `failureReason`:

  | Outcome | `failureReason` note | Meaning |
  |---|---|---|
  | `NOT_PRESENT` | "no rule was left behind" | the firewall positively said there is no such rule |
  | `REMOVED` | "the partially applied rule was removed and confirmed absent" | removal confirmed |
  | `PRESENT_UNREMOVED` | "CLEANUP_UNCONFIRMED: a rule may remain; flagged for reconciliation" | the rule is or may still be there |

  A `PRESENT_UNREMOVED` rule is flagged as `recovery.lateRule = PRESENT_UNREMOVED`. The existing reconciliation pass
  retries its removal with back-off, and `GET /api/containment/recovery` lists it as needing investigation. A failed
  cleanup is never reported as clean.
- **When no cleanup is needed.** An adapter that refuses before running anything (gate closed, invalid input) is
  recorded `FAILED` with cleanup `NOT_APPLIED`, and nothing is inspected.
- **Release (rollback or TTL expiry).**
  - `removeRule` is called. For real adapters the rule is then looked up again.
  - A rule still present after a "successful" removal is `ROLLBACK_FAILED` (`RELEASE_NOT_VERIFIED`) and can be
    retried.
  - A rule already deleted outside SentinelAI is a successful release: Windows treats netsh's "No rules match" as
    absent, and Linux treats `iptables -C` "Bad rule" as absent.
  - Any other error (access denied, sudo password needed, timeout) is a failure. The Linux adapter used to report
    "already absent" whenever its presence check failed for any reason.
  - Releasing an already released action is refused (400).
- **Exit codes.** Process errors such as `ENOENT` / `ETIMEDOUT` are recorded as exit code 1. The string code used to
  make the `FAILED` / `ROLLBACK_FAILED` save itself fail, leaving the action unrecorded.

The lifecycle (`REQUESTED -> VALIDATING -> APPROVED -> APPLYING -> ACTIVE -> ROLLING_BACK -> ROLLED_BACK`, with
`FAILED`, `REJECTED`, `EXPIRING` and `ROLLBACK_FAILED`) is unchanged.

### Defects fixed while verifying (2026-11-13)

1. `ContainmentAction.enforcementBackend` did not allow `linux-iptables`, so every real Linux action would have
   failed validation on its first save.
2. Linux release reported success when its presence check failed for any reason.
3. Windows recorded string process codes as the exit code, which made the failure record unsaveable.
4. A failed or unverified apply ignored the cleanup result. A leftover rule could go unreported.
5. Releases were not confirmed. A rule left after a "successful" removal was reported as released.
6. Windows treated a rule already removed outside SentinelAI as a release failure, which stayed failed forever.
7. Windows verification accepted any rule with the right name, whatever its direction, action or address.
8. Windows rule names had no length bound and accepted a bare prefix.
9. netsh and wsl were started by bare name.
10. The containment status reported the Windows enable flag instead of the adapter actually in use.
11. The dashboard and the containment labels treated only `windows-firewall` as real, so an active Linux rule would
    have been called simulated.

### How it is verified (mocked commands only)

```bash
cd backend
npx jest --runInBand tests/firewallContainmentVerification.test.js tests/realFirewallAdapters.test.js tests/firewallExecFile.test.js tests/windowsFirewallSafety.test.js tests/containmentAPI.test.js
```

```bash
cd frontend
node --test tests/containmentLabels.test.mjs tests/capabilities.test.mjs
```

`tests/firewallContainmentVerification.test.js` replaces `child_process.execFile` for the whole file with a recorder
that refuses to run anything. Its last check asserts that the only `execFile` calls were three deliberate probes of
the default runners, all refused.

The real `WindowsFirewallAdapter` and `LinuxIptablesAdapter` run against in-memory fake firewalls that answer like
netsh and iptables, through the real containment service, state machine and an in-memory MongoDB. Covered, for both
adapters:
- valid request -> ACTIVE
- invalid IP, missing or insufficient authorisation, protected targets: no command runs
- gate closed
- apply failure
- verification failure
- partial apply, then cleanup
- failed cleanup, then reconciliation
- explicit release; repeated release
- removal that leaves the rule
- removal failure
- duplicate and concurrent requests
- invalid durations; TTL expiry
- audit event order
- the status endpoint

Also covered:
- command construction
- executable allowlisting
- injection attempts
- the factory's gate (backend, flag, host-bound phrase, dry run)
- the mock default
- the Capability Status entries

`tests/containmentAPI.test.js` checks the HTTP boundary: unauthenticated, honeypot-key, viewer and forged-token
requests are refused, and the adapter is never called.

**No real firewall command has been run and no real rule has been created on any machine.** Real enforcement stays
off: verifying it needs the owner's authorisation and an isolated lab host, and these tests cannot show that.
