# Supervised deception rotator (WSL Cowrie lab)

Applies the Q-learner's recommended persona to the WSL Cowrie lab on a schedule. The unit runs the same
`honeypot/deception_rotator.py` the demo uses, through `scripts/demo/cowrie-demo-mode.sh rotate`, under a
systemd **user** unit. **It is never enabled automatically.** Installing it changes nothing until you run `enable`.

## What it does each interval (default 60 minutes)

1. It asks the backend for the pending decision (`/api/honeypot/ingest/deception/recommendation`, honeypot key).
   The backend persists one PENDING decision per served persona and supersedes it after `DECEPTION_DECISION_TTL_MINUTES` (120 by default).
   Keep the interval shorter than that TTL.
2. **Keep:** if the decision is to keep the current persona, the rotator acknowledges it.
3. **Defer:** if attacker sessions are open, the switch waits for the next interval. The unit never passes `--force`.
4. **Switch.** The rotator refuses unless a restart command and the built persona filesystem are available.
   It rewrites `cowrie.cfg` (keeping the current binding) and restarts Cowrie. The connection opened before the restart must have been dropped, and Cowrie must answer with the new persona's SSH banner.
   Only then is the decision recorded **APPLIED**. Otherwise `cowrie.cfg` is restored, Cowrie is restarted, and the decision is marked **FAILED**.
5. A lock next to `cowrie.cfg` stops the unit and a manual `rotate --once` from switching at the same time.

Limitation: `centos_7` and `aws_ec2` send the same SSH banner. For that pair, the restart proof and the
`cowrie.cfg` header establish which persona is served; the banner does not.

## Safety properties

* **Not enabled by default.** `install` only writes the unit file; `enable` is a separate, explicit step.
* **No wildcard binding.** The loop refuses to start (exit 3) if Cowrie listens on `0.0.0.0` or `::`.
  Use `cowrie-demo-mode.sh off` (127.0.0.1) or `on` (WSL NAT address, reachable from this Windows host only).
* **Real firewall enforcement is unchanged.** The rotator only rewrites `cowrie.cfg`, restarts Cowrie and calls the honeypot-scoped backend endpoints.
* **Stop is graceful.** `disable` sends SIGTERM. A switch in progress finishes (including any restore) before the rotator exits, within 330 s.
  A sleeping rotator exits at once. Cowrie keeps running (`KillMode=process`).
* **Failure handling.** Backend outages are logged and retried at the next interval.
  Five unexpected errors in a row end the loop with code 1; systemd restarts it after 2 minutes, at most 3 times an hour.
  A failed switch whose restore restart also failed ends the loop with code 3, which systemd does **not** restart (see Recovery).
* **Crash recovery.** If the rotator is killed mid-switch, systemd restarts it after 2 minutes.
  The restarted rotator takes over the dead process's lock at once (its PID no longer exists).
  It then records the persona `cowrie.cfg` actually serves, and the interrupted decision stays PENDING until it is applied or expires; it is never marked APPLIED.
  `rotator-ctl.sh enable` clears systemd's start counter, so an explicit enable after a recovery always restores the full restart budget.

## Procedures (inside WSL)

```bash
bash scripts/rotator/rotator-ctl.sh install    # writes ~/.config/systemd/user/sentinel-rotator.service; not enabled
bash scripts/rotator/rotator-ctl.sh enable     # explicit opt-in: starts now and whenever WSL starts
bash scripts/rotator/rotator-ctl.sh status     # unit state, persona served, binding, last rotation result
bash scripts/rotator/rotator-ctl.sh logs 100   # recent rotator log lines (journalctl --user)
bash scripts/rotator/rotator-ctl.sh disable    # graceful stop + disable
bash scripts/rotator/rotator-ctl.sh uninstall  # disable and remove the unit file
```

Overrides go in `~/.config/sentinelai/rotator.env` (mode 600), for example `ROTATOR_INTERVAL=30`.
`COWRIE_HOME`, `COWRIE_ENV` and `BACKEND_PORT` are also read from there. The honeypot key is read from `backend/.env`, as in demo mode.

### Recovery

`status` shows `"state": "needs_recovery"` and the unit is `failed` (exit code 3). This means a switch failed and Cowrie did not come back with the restored `cowrie.cfg`.

```bash
bash scripts/rotator/rotator-ctl.sh recover    # stops the unit, restarts Cowrie with the restored cfg, shows status
bash scripts/demo/cowrie-demo-mode.sh status   # Cowrie answering? blocker thread alive?
bash scripts/rotator/rotator-ctl.sh enable     # only after Cowrie serves again
```

The failed decision is already FAILED in the backend. The next run draws a new decision.

### Manual use is unchanged

`bash scripts/demo/cowrie-demo-mode.sh rotate --once [--force]` applies one recommendation now, with the same checks.
If the unit is mid-switch at that moment, the manual run skips (lock held) and says so.

## Keeping WSL running

**What WSL actually does.** WSL stops a distro a few seconds after its last `wsl.exe` process exits. Lingering does not prevent this.
When it stops, the rotator, Cowrie and its blocker all stop with it.
When WSL next starts (any `wsl` command, or opening an Ubuntu terminal), the enabled unit starts again on its own. Its `ExecStartPre` (`cowrie-demo-mode.sh ensure`) also starts Cowrie if it is down:
* an "on" binding is moved to the current WSL address, so a changed address doesn't stop Cowrie from binding;
* loopback is kept;
* a wildcard binding is refused.

So rotation is automatic **while WSL is running**, and pauses while it isn't.

**Optional keep-alive (Windows).** One hidden `wsl.exe … sleep infinity` process keeps the distro running. The script changes no Windows settings and lasts until you stop it, sign out or reboot.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 start
powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 status
powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 stop
```

`start` also repairs the WSL user manager if a forced restart left it failed: it restarts `user@<uid>` as the distro's root, which needs no Windows administrator rights. It then reports the rotator and Cowrie state. `status` shows the same, plus the sign-in registration.

To start it at every sign-in, register it as a per-user scheduled task. It runs with limited rights and needs no admin, but it is a change to your Windows setup, so nothing here registers it for you:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 register -DryRun   # preview
powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 register
powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 registration
powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 unregister         # disable
```

The backend and AI engine run on Windows (`scripts/demo/start-demo.ps1`). While they are down, every round is logged as a transient error and nothing is switched.

**What keeps WSL up in practice (observed 2026-11-12).** While `scripts/demo/start-demo.ps1` is running, WSL stays up with no WSL window open: its log parser reads Cowrie's log through `\wsl.localhost`.
Without the demo stack, WSL stopped within about a minute of the last window closing.

**If the rotator does not come back after WSL restarts.** Check with `systemctl --user is-system-running`. A forced `wsl --terminate` followed by an immediate restart can leave the user manager failed (`journalctl -u user@1000`: "Failed to spawn executor: Device or resource busy"), so no user unit starts.
Fix it from Windows:

```powershell
wsl -d Ubuntu -u root -- systemctl restart user@1000.service
```

Then the enabled unit starts on its own, and its `ensure` step brings Cowrie back.
