#!/usr/bin/env python3
"""
SentinelAI deception rotator: applies the Q-learner's recommended Cowrie persona.

Every --interval minutes it asks the backend for the recommended next persona
(GET /api/honeypot/deception/recommendation). When it differs from the persona being served it:
  1. rewrites cowrie.cfg with switch_profile.generate_config,
  2. restarts Cowrie with --restart-cmd (run without a shell; skipped if not given),
  3. records the persona now served (PUT /api/honeypot/deception/profile), so the next sessions'
     rewards are credited to it.
This closes the learning loop: the learner explores (epsilon-greedy) and exploits personas that keep
attackers engaged, instead of only scoring the one persona configured by hand.

  SENTINEL_ROTATOR_EMAIL=admin@... SENTINEL_ROTATOR_PASSWORD=... \\
    python deception_rotator.py --backend http://127.0.0.1:5000 --restart-cmd "systemctl restart cowrie"
  python deception_rotator.py --once --dry-run      # show what would change

Needs an admin account (recording the persona requires settings:write). The password is read from the
environment or a prompt and never logged.
"""
import argparse
import getpass
import logging
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import switch_profile  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sentinel.rotator")


class BackendClient:
    """CSRF handshake + login, then bearer-authenticated calls; re-logs in once on 401."""

    def __init__(self, base, email, password, origin):
        self.base, self.email, self._password, self.origin = base.rstrip("/"), email, password, origin
        self.http = requests.Session()
        self.token = None

    def login(self):
        csrf = self.http.get(f"{self.base}/api/auth/csrf", headers={"Origin": self.origin}, timeout=10)
        csrf.raise_for_status()
        resp = self.http.post(f"{self.base}/api/auth/login", json={"email": self.email, "password": self._password},
                              headers={"Origin": self.origin, "X-CSRF-Token": csrf.json()["data"]["csrfToken"]}, timeout=10)
        if resp.status_code != 200:
            raise RuntimeError(f"Backend login failed (HTTP {resp.status_code})")
        self.token = resp.json()["data"]["token"]

    def call(self, method, path, **kw):
        for attempt in (1, 2):
            resp = self.http.request(method, f"{self.base}{path}", headers={"Authorization": f"Bearer {self.token}"},
                                     timeout=30, **kw)
            if resp.status_code != 401 or attempt == 2:
                return resp
            self.login()


def run_restart(cmd: str):
    if not cmd:
        log.info("No --restart-cmd given: restart Cowrie yourself to serve the new persona")
        return True
    result = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        log.error("Restart command failed (exit %s): %s", result.returncode, result.stderr.strip()[:200])
        return False
    return True


def rotate_once(client: BackendClient, cfg_path: Path, restart_cmd: str, dry_run: bool) -> dict:
    resp = client.call("GET", "/api/honeypot/deception/recommendation")
    if resp.status_code != 200:
        raise RuntimeError(f"Recommendation unavailable (HTTP {resp.status_code})")
    data = resp.json()["data"]
    active, nxt = data["activeProfile"], data["nextProfile"]
    if nxt == active:
        log.info("Keeping persona %s (recommended again)", active)
        return {"changed": False, "active": active}
    log.info("Switching persona %s -> %s%s", active, nxt, " (exploration)" if data.get("explored") else "")
    if dry_run:
        return {"changed": False, "active": active, "would_switch_to": nxt}
    switch_profile.CFG_PATH = cfg_path
    switch_profile.generate_config(nxt)
    if not run_restart(restart_cmd):
        return {"changed": False, "active": active, "error": "restart failed; persona not recorded"}
    rec = client.call("PUT", "/api/honeypot/deception/profile", json={"profile": nxt})
    if rec.status_code != 200:
        raise RuntimeError(f"Recording the persona failed (HTTP {rec.status_code})")
    return {"changed": True, "active": nxt, "previous": active}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--backend", default=os.getenv("SENTINEL_BACKEND_URL", "http://127.0.0.1:5000"))
    ap.add_argument("--origin", default="http://localhost:3000", help="must equal the backend's CLIENT_URL")
    ap.add_argument("--email", default=os.getenv("SENTINEL_ROTATOR_EMAIL"))
    ap.add_argument("--cfg", default=str(switch_profile.CFG_PATH), help="cowrie.cfg to rewrite")
    ap.add_argument("--restart-cmd", default=os.getenv("COWRIE_RESTART_CMD", ""))
    ap.add_argument("--interval", type=float, default=60.0, help="minutes between rotations")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not args.email:
        ap.error("--email (or SENTINEL_ROTATOR_EMAIL) is required")
    password = os.getenv("SENTINEL_ROTATOR_PASSWORD") or getpass.getpass(f"Password for {args.email}: ")

    client = BackendClient(args.backend, args.email, password, args.origin)
    client.login()
    while True:
        try:
            log.info("Rotation result: %s", rotate_once(client, Path(args.cfg), args.restart_cmd, args.dry_run))
        except (requests.RequestException, RuntimeError) as e:
            log.error("Rotation failed: %s", e)
        if args.once:
            return
        time.sleep(args.interval * 60)


if __name__ == "__main__":
    main()
