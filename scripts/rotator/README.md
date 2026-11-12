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
