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

## Enforcement

| Kind | What it is | State |
|---|---|---|
| Simulated | `MockContainmentAdapter`: records a rule, changes nothing | **default** |
| Cowrie deny-list | the honeypot refuses deny-listed sources | real, honeypot only |
| Host firewall | `WindowsFirewallAdapter` (netsh) or `LinuxIptablesAdapter` (iptables/ip6tables, optionally through `wsl -d Ubuntu -- sudo -n`) | implemented, **not enabled** |
| Unavailable | a real backend was requested but the gate refused it | falls back to simulated |

Real enforcement needs **all** of these:
1. `CONTAINMENT_BACKEND=windows-firewall` or `linux-iptables`
2. that backend's flag: `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true` or `ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT=true`
3. `CONTAINMENT_REAL_ENFORCEMENT_CONFIRM=I-AUTHORIZE-FIREWALL-CHANGES-ON-<hostname>` (bound to the machine)
4. not a test run and not `CONTAINMENT_DRY_RUN`
5. `CONTAINMENT_PROTECTED_TARGETS` set, and `HONEYPOT_AUTOBLOCK_MODE=approve` (startup refuses otherwise)

Safety properties of the real adapters:
- **No shell.** Commands run without a shell, from argument arrays.
- **Strict inputs.** Targets must be valid IPs or CIDRs, and rule names must be `SentinelAI-Rule-<id>`. Only
  SentinelAI-tagged rules are ever checked or removed.
- **No duplicates.** The Linux adapter checks with `-C` before inserting.
- **Verified rules.** After every apply, the containment service looks the rule up again
  (`requiresPostApplyVerification`). An unverified rule fails the action with `ENFORCEMENT_NOT_VERIFIED` and is
  removed.
- **Full audit.** Requested, approved, applied, verified or not, failed, and released actions are all audited.

Tests (`tests/realFirewallAdapters.test.js`) use mocked command execution only. **No real firewall rule has been
created on any machine.** The dashboard therefore reports host-firewall protection as not enabled.
