# Honeypot personas

Cowrie emulates a **Linux** shell. A persona changes the SSH banner, hostname, `uname` strings, `/etc/os-release`,
`/etc/motd` and the planted files (`honeypot/build_honeyfs.py`). It cannot change the shell itself.

| Persona | OS identity | SSH banner | Status |
|---|---|---|---|
| `ubuntu_22` | Ubuntu 22.04 LTS | OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 | servable |
| `debian_11` | Debian GNU/Linux 11 | OpenSSH_8.4p1 Debian-5+deb11u3 | servable |
| `centos_7` | CentOS Linux 7 | OpenSSH_7.4 | servable |
| `aws_ec2` | Amazon Linux 2 | OpenSSH_7.4 (same as `centos_7`) | servable |
| `raspberry_pi` | Raspbian GNU/Linux 11 | OpenSSH_8.4p1 Raspbian | servable |
| `windows_srv` | Windows Server 2019 | — | **unsupported** |

## The Windows persona (resolution of limitation 5)

A Windows banner over a Linux shell gives itself away at the first command, and it would falsely claim a Windows
host. A genuine Windows target would need an isolated Windows VM with a restricted command environment. That is not
available here, and exposing the real Windows host is never acceptable.

`windows_srv` is therefore **unsupported** under every setting:
- **Learner:** never recommends it (`UNSUPPORTED_PROFILES`). `DECEPTION_EXCLUDED_PROFILES` can only exclude more
  personas.
- **Profile switcher:** `switch_profile.py` never writes it (`--allow-unservable` no longer bypasses this).
- **Backend:** refuses to record it as served and does not offer it.
- **Arena:** refuses it as a baseline.
- **Rotator:** marks a decision for it FAILED.

It stays in the Q-table's keys only, so the shipped seed and history keep their shape.

## Verification

`ai-engine/tests/test_rollback_rehearsal.py` checks every selectable persona:
- **Consistency:** banner, OS identity and kernel agree between `switch_profile.py` and the learner.
- **Served behaviour:** the generated `cowrie.cfg` is served from a loopback endpoint and checked with the rotator's
  own `verify_served`, which is what an SSH client actually receives.
- **Wrong banners:** a mismatching banner is rejected.

`centos_7` and `aws_ec2` share a banner. The rotator also requires the pre-restart connection to have been dropped.

These tests use a local banner server, not the live Cowrie: the live honeypot is never touched by tests. The
rotator itself verifies the live banner after every real switch (PR #26).

## Simulated Windows persona (Rank 7, 2026-11-14)

`windows_srv` now has a **Windows-like shell simulation** (`honeypot/windows_persona/`). It is experimental and
**not production-eligible**. Everything in "The Windows persona" above still holds for production: the learner,
persona policy v2, the rotator, `switch_profile.py` and the backend still refuse it.

| Field | Value |
|---|---|
| `supported` | true (implemented; tests pass) |
| `experimental` | true |
| `productionEligible` | false |
| `servingEnabled` | false (the Cowrie hook is off by default and not deployed) |

### Why it is still Cowrie, and what is simulated

Cowrie 3.1.3 (checked in the WSL install) is an SSH/Telnet honeypot. Its own shell parses input as POSIX shell
and serves a pickled Linux filesystem, so renaming a persona cannot make it look like Windows. The simulation keeps
Cowrie for SSH, authentication, logging and the deny-list, and replaces only the **shell object** Cowrie creates for
each session (`cmdstack = [honeypot.HoneyPotShell(protocol)]`) with `WindowsCowrieShell`. That shell implements the
same interface Cowrie calls: `lineReceived`, `showPrompt`, `resume`, `eofReceived`, `handle_CTRL_C`, `handle_TAB`,
`interactive`, `cwd`, `environ`, `exported` and `last_exit_code`.

**Simulated:**
- cmd.exe-style and PowerShell-style prompts and syntax
- an allowlist of commands with fictional, consistent output
- a fictional identity (`WIN-SRV19-DC01`, Windows Server 2019 Datacenter 10.0.17763, `Administrator`) and fictional
  addresses (`10.20.30.0/24`)
- an in-memory filesystem

**Not simulated:**
- the Windows kernel, real cmd.exe or a real PowerShell runtime
- the registry, WMI, services or Active Directory
- RDP, SMB or WinRM: `netstat` *prints* listeners on 3389, 445 and 5985, but nothing listens on them
- scripts (`.bat`/`.ps1`) and real network I/O

Cowrie's SSH key exchange and host keys are unchanged, so a careful attacker can still tell it apart from a real host.

### Components

| File | Role |
|---|---|
| `persona.py` | identity, network and status flags (matches `deception_scorer.PROFILES` and `switch_profile.PROFILES`) |
| `vfs.py` | isolated in-memory filesystem |
| `shell.py` | parser and command allowlist |
| `telemetry.py` | intent and ATT&CK rules |
| `cowrie_shell.py` | the Cowrie shell adapter |
| `cowrie_hook.py` | opt-in install and uninstall |
| `honeypot/cowrie/sentinelwindows.py` | Cowrie output plugin that calls the hook (not installed; not in `cowrie.cfg`) |

### Commands (allowlist)

- **cmd:** `dir` (`/a`, `/b`, wildcards), `cd`/`chdir` (including `cd..` and `cd\`), `type`, `more`, `echo`, `set`,
  `cls`, `mkdir`/`md`, `del`/`erase`, `date /t`, `time /t`, `help`, `ver`, `exit`.
- **Programs (cmd and PowerShell):**
  - `whoami` (`/all`, `/priv`, `/groups`), `hostname`, `systeminfo`, `ipconfig` (`/all`)
  - `ping` (simulated: fictional neighbours reply, everything else times out, unknown names fail)
  - `netstat` (`-a`, `-n`, `-o`), `tasklist` (`/svc`), `sc query [name]`
  - `net user|localgroup|share|view|accounts|start|use`; account, group or service changes return "Access is denied"
  - `findstr`/`find`; `certutil -urlcache` (always fails to resolve: nothing is downloaded)
  - `cmd /c|/k`: the text after the switch is taken as typed, with cmd.exe's quote rule (leading quote and last
    quote removed), so `cmd /c "whoami & hostname"` runs both. `/c` runs in an isolated child (own environment
    copy and directory); `/k` keeps the child's directory and environment, as the nested shell stays open
  - `powershell` (interactive, `-c`/`-Command`, `-enc`: decoded and simulated in an isolated child, never executed)
- **PowerShell:**
  - `Get-ComputerInfo`, `Get-Process`, `Get-Service`, `Get-Location`, `Set-Location`, `Get-ChildItem`, `Get-Content`
  - `Get-LocalUser`, `Get-NetIPAddress`, `Invoke-WebRequest` (always fails)
  - `Clear-Host`, `Write-Output`, `Select-String`, `Select-Object -First/-Last`, `Format-*`/`Out-*`/`Where-Object`
    (pass-through)
  - `$env:VAR`, `$PSVersionTable`, and the usual aliases (`ls`, `dir`, `gci`, `cat`, `type`, `ps`, `iwr`, `curl`,
    `wget`, ...). In PowerShell, `sc` is `Set-Content` (not supported), as on Windows.
- **Anything else** gets the genuine-looking error ("'x' is not recognized as an internal or external command", or
  PowerShell's CommandNotFoundException). There is no generic output.

### Virtual filesystem and security boundaries

**Filesystem layout.** A per-session copy of a fictional tree: `C:\Windows\System32` (including `drivers\etc\hosts`
and a locked `config\SAM`), `C:\Users\Administrator` (Desktop, Documents, hidden AppData and NTUSER.DAT),
`C:\Users\Public`, `C:\Program Files`, `C:\ProgramData` (OpenSSH config), `C:\inetpub\wwwroot` (a `web.config` with a
**canary** connection string), `C:\Windows\Panther\unattend.xml` (canary) and `C:\Temp`.

**Path rules:**
- paths are case-insensitive, accept `\` and `/`, and are shown in their stored case
- `C:` and drive-relative forms work; `..` stops at `C:\`
- other drives, UNC paths, alternate data streams, device names (`CON`, `NUL`, ...), control or wildcard characters
  in names, and paths over 260 characters are rejected

**Write limits.** Writes (`>`, `>>`, `mkdir`, `del`) work only under `C:\Users\Administrator` and `C:\Temp`, capped at
64 KB per file and 256 new entries per session. System files are "Access is denied". Nothing persists between
sessions.

**No host access:**
- The package imports no `os`, `subprocess`, `socket`, `pathlib` or `io`, and calls no `open`, `eval`, `exec` or
  `compile`. This is enforced by an AST test.
- Chaining (`&`, `&&`, `||`, `|`), redirection and `%VAR%` (from the simulated environment) are parsed by the
  simulator itself.
- `$(...)` and backticks are inert text. `^` escapes are honoured.
- Lines over 8,191 characters, more than 32 statements and more than 3 nested `cmd /c`/`powershell -c` levels are
  bounded.

### SentinelAI integration

- **Telemetry:**
  - **Ingested by SentinelAI:** Cowrie's standard `cowrie.command.input` (every line) and `cowrie.command.failed`
    (unknown programs). The parser forwards them, and the backend stores the command and computes intent and ATT&CK
    itself.
  - **Cowrie-side only (not ingested):** `sentinel.windows.command` (name, category, intent, ATT&CK ids,
    `simulated: true`) and `sentinel.windows.limit` exist only in Cowrie's JSON log; the parser has no handler for
    them. Ingesting them would duplicate the command records.
- **Intent:**
  - The parser (`classify_session_intent`) and the backend ingest (`utils/windowsPersona.js` `intentForSession`)
    apply Windows rules **only for sessions served as `windows_srv`** and only where the Linux rules found nothing.
  - Linux sessions are classified exactly as before.
  - The Python and JavaScript rules are kept identical by a shared corpus
    (`ai-engine/tests/fixtures/windows_intent_corpus.json`).
- **ATT&CK (Rank 8: persona-gated):** the Windows rules (`utils/windowsPersona.js` `WINDOWS_COMMAND_TECHNIQUES`)
  apply **only to sessions served as `windows_srv`**. A Linux session gets exactly the Linux rules, even for command
  names both systems share. Ids, names and tactics come from the verified ATT&CK v20.1 table
  (`backend/utils/attackTechniques.js`); event-log clearing is T1685.005, formerly T1070.001. Clearing Linux
  system logs (deleting, shredding or truncating `/var/log` files, `journalctl --vacuum-*`) is T1685.006 and comes
  from the Linux rules.
- **Scoring:**
  - A session served by `windows_srv` is **scored but never learned**: no Q-value, episode, count or file write in V1;
    V2 does not observe it; the learner keeps its last servable state (`notLearnedReason: EXPERIMENTAL_PERSONA`).
  - **Rank 8 (F1):** the session served *after* a `windows_srv` session is not learned either
    (`notLearnedReason: UNSUPPORTED_PREVIOUS_PERSONA`), because its Q-learning state would be `windows_srv`.
    `DeceptionQLearner.update` also refuses any unsupported state, action or next state before any side effect, so an
    experimental persona can never enter the V1 table, whatever the caller.
  - This closes a latent path: before Rank 7, such a session would have been learned into the production Q-table.
  - Linux sessions are scored and learned exactly as before.
- **Session ML:** `windows_srv` still maps to `persona_unknown` (the classifier was built on the Linux personas).
- **Frontend:** every view that names the served persona shows `windows_srv (simulated Windows shell, experimental)`.
- **Capability Status:** two entries.
  - `windows_persona_simulation`: Implemented and tested (simulated), read from the newest
    `audit/rank7_windows_persona/run_*/rank7_status.json`.
  - `windows_persona`: production serving, Implemented, not enabled; `productionEligible: false`.

### Tests

| Behaviour class | Where |
|---|---|
| Unit and security | `ai-engine/tests/test_windows_persona.py`: identity, filesystem, every command, errors, syntax, prompts, injection with process/socket/file/eval patched to fail, AST audit, adapter with a fake protocol, hook, parser, scoring, V1/V2 exclusion, Rank 6 guard |
| Backend | `backend/tests/rank7WindowsPersona.test.js`: intent parity, ATT&CK, session-gated intent on in-memory MongoDB, metadata, Capability Status |
| Frontend | `frontend/tests/personaLabels.test.mjs` |
| Integration with Cowrie 3.1.3 | `ai-engine/tests/cowrie_windows_integration.py`, run with Cowrie's own interpreter: real `HoneyPotInteractiveProtocol`/`HoneyPotExecProtocol` objects with Cowrie's fake transport and event capture. No listener, no live service, no files written |
| Live | none: the persona has never been served |

Run the integration check:

```bash
cd <cowrie>; ../env/bin/python <sentinelai>/ai-engine/tests/cowrie_windows_integration.py <sentinelai>/honeypot
```

Write the evidence:

```bash
cd ai-engine; .venv/Scripts/python evaluation/rank7_windows_evidence.py --engine-xml ... --backend-json ... --frontend-summary ... --cowrie-result ...
```

### Enabling it (owner decision; not done)

All of these would be required:
1. Install the plugin and enable `[output_sentinelwindows] enabled = true` with `allow_experimental = true`.
2. Change `switch_profile.py` so it can write the persona header (it refuses today).
3. Accept that its sessions are evidence of nothing for V1/V2 (never learned).

Production eligibility would need a separate decision with live, external evidence.

### Rank 8 hardening (2026-11-19)

**F3, quoting:** `cmd /c` / `cmd /k` used to re-join tokens, so `cmd /c "whoami & hostname"` was one unknown
command. Fixed as described above.

**F4, environment isolation:** a nested shell used to share the parent's environment dictionary, so
`cmd /c set X=1` leaked into the session. Nested shells now get their own environment copy and working directory;
only `cmd /k` adopts them, on purpose.

**Malformed quoting:** a line containing only `"` raised an exception inside the simulator, which would break the
Cowrie session. It now gets the cmd.exe error, and an unterminated quote runs to the end of the statement as in cmd.

**Hard limits** (`honeypot/windows_persona/shell.py`, `vfs.py`). When a limit is hit, the line stops; `Result.limits`
says which limit, the adapter logs a Cowrie-side `sentinel.windows.limit` event, and the exit code is 1.

| Limit | Value |
|---|---|
| Line length | 8,191 characters |
| Statements per line | 32 |
| Events per line, shared by every nested shell | 32 (new) |
| Nesting depth | 3 |
| Output per line | 64 KB |
| Redirections per statement | 8; repeated targets follow cmd: all are created, the last gets the output (new) |
| Bytes stored per session, created or modified files | 1 MiB (new) |
| Per file | 64 KB |
| New entries per session | 256 |

**F5, reverse-shell classification:** an encoded PowerShell command counts as a reverse shell only with an explicit
`-enc` / `-EncodedCommand` flag on a `powershell` invocation AND a reverse-shell indicator in the decoded payload
(`TCPClient`, `Invoke-PowerShellTcp`, `$x.GetStream()`). A benign encoded command is classified by what it decodes to.
`echo -e <long text>` is no longer a reverse shell. Python and JavaScript share one test corpus.

**Security tests** (`ai-engine/tests/test_windows_hardening.py`):
- Process creation, sockets, DNS, file opening, `os` file operations, `eval` / `exec` / `compile`, `import_module`
  and new imports are patched to fail while attack lines run: 0 calls.
- Malformed, Unicode and very long input never raises.

The in-process Cowrie integration check (`ai-engine/tests/cowrie_windows_integration.py`) needs Cowrie's WSL
interpreter and was **not re-run in Rank 8**, to avoid interacting with WSL.
