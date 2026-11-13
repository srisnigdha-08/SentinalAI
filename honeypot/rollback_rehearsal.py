#!/usr/bin/env python3
"""
Isolated rollback rehearsal for the deception rotator (docs/PERSONA_POLICY_V2.md §7, gate 4 preparation).

Drives the REAL deception_rotator.rotate_once against:
  * a disposable cowrie.cfg in a temporary directory (written by the real switch_profile),
  * a local fake SSH endpoint on 127.0.0.1 (a banner server that "restarts" when the restart command runs and then
    serves the banner of the persona named in cowrie.cfg, or misbehaves on purpose),
  * an in-memory fake backend that records APPLIED / FAILED outcomes.
It never connects to the live Cowrie, never touches ~/sentinelai-cowrie-test, never writes a Q-table and never
calls the real backend. Scenarios:
  success           the persona switches, the banner matches -> APPLIED, profile recorded
  failed_apply      the restart command exits non-zero        -> FAILED, previous cowrie.cfg restored
  timeout           after restart nothing answers             -> FAILED (no banner), cfg restored
  invalid_persona   the recommendation is windows_srv         -> FAILED (unsupported), cfg untouched
  restart_noop      restart "succeeds" but Cowrie keeps going -> FAILED (watch connection still alive), cfg restored
  wrong_banner      Cowrie restarts with the old banner       -> FAILED (banner mismatch), cfg restored

  python honeypot/rollback_rehearsal.py --json rehearsal.json
This is an ISOLATED rehearsal: it proves the rollback logic, not a rollback on the live honeypot (gate 4 still
needs the live rehearsal recorded by the owner).
"""
import argparse, json, os, shutil, socket, sys, tempfile, threading, time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import deception_rotator as rot  # noqa: E402
import switch_profile  # noqa: E402


class FakeCowrie:
    """Banner server. mode: normal | silent_after_restart | ignore_restart | wrong_banner."""

    def __init__(self, cfg_path: Path, marker: Path, mode: str = "normal"):
        self.cfg_path, self.marker, self.mode = cfg_path, marker, mode
        self.lock = threading.Lock()
        self.conns = []
        self.restarts = 0
        self.silent = False
        self.banner = self._banner_for_cfg()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self._serve, daemon=True), threading.Thread(target=self._watch, daemon=True)]
        for t in self.threads:
            t.start()

    def _banner_for_cfg(self):
        persona = rot.served_persona(self.cfg_path)
        return switch_profile.PROFILES[persona]["banner"] if persona in switch_profile.PROFILES else "SSH-2.0-unknown"

    def _serve(self):
        while not self.stop.is_set():
            try:
                c, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            with self.lock:
                if self.silent:
                    c.close()
                    continue
                try:
                    c.sendall((self.banner + "\r\n").encode())
                except OSError:
                    c.close()
                    continue
                self.conns.append(c)

    def _watch(self):
        """The restart command creates the marker file; this simulates Cowrie restarting."""
        while not self.stop.is_set():
            if self.marker.exists():
                self.marker.unlink()
                with self.lock:
                    self.restarts += 1
                    if self.mode == "ignore_restart":
                        continue  # nothing restarts: open connections survive
                    for c in self.conns:
                        try:
                            c.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        c.close()
                    self.conns = []
                    if self.mode == "silent_after_restart" and self.restarts == 1:
                        self.silent = True
                    elif self.mode == "wrong_banner" and self.restarts == 1:
                        pass  # keeps the old banner
                    else:
                        self.silent = False
                        self.banner = self._banner_for_cfg()
            time.sleep(0.05)

    def close(self):
        self.stop.set()
        with self.lock:
            for c in self.conns:
                try:
                    c.close()
                except OSError:
                    pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        for t in self.threads:
            t.join(timeout=2)


class FakeBackend:
    """What rotate_once needs from the backend; records the outcome of the decision."""
    RECOMMENDATION, PROFILE = "/rec", "/profile"

    def __init__(self, active: str, nxt: str):
        self.active, self.nxt = active, nxt
        self.recorded, self.failed, self.acknowledged = [], [], []

    class _R:
        def __init__(self, code, data=None):
            self.status_code, self._data = code, data

        def json(self):
            return {"data": self._data}

    def call(self, method, path, **kw):
        if method == "GET" and path == self.RECOMMENDATION:
            return self._R(200, {"activeProfile": self.active, "nextProfile": self.nxt, "decisionId": "rehearsal-1", "activeSessions": 0})
        if method == "PUT" and path == self.PROFILE:
            body = kw.get("json") or {}
            if body.get("profile") in switch_profile.UNSERVABLE:
                return self._R(400)
            self.recorded.append(body.get("profile"))
            self.active = body.get("profile")
            return self._R(200)
        if method == "POST" and "fail" in path:
            self.failed.append((kw.get("json") or {}).get("reason"))
            return self._R(200)
        if method == "POST" and "ack" in path:
            self.acknowledged.append(kw.get("json"))
            return self._R(200)
        return self._R(404)


def _patch_backend_calls(backend):
    """rotate_once reports outcomes through module helpers; route them to the fake backend."""
    rot._fail = lambda client, decision_id, reason: backend.failed.append(reason)
    rot._acknowledge = lambda client, profile, decision_id: backend.acknowledged.append(profile)


SCENARIOS = {
    # name: (fake cowrie mode, recommended persona, restart exit code, expected outcome)
    "success": ("normal", "ubuntu_22", 0, "APPLIED"),
    "failed_apply": ("normal", "ubuntu_22", 3, "FAILED"),
    "timeout": ("silent_after_restart", "ubuntu_22", 0, "FAILED"),
    "invalid_persona": ("normal", "windows_srv", 0, "FAILED"),
    "restart_noop": ("ignore_restart", "ubuntu_22", 0, "FAILED"),
    "wrong_banner": ("wrong_banner", "ubuntu_22", 0, "FAILED"),
}


def run_scenario(name, verify_timeout=2.0):
    mode, nxt, exit_code, expected = SCENARIOS[name]
    tmp = Path(tempfile.mkdtemp(prefix=f"rehearsal_{name}_"))
    cowrie = None
    saved = (rot._fail, rot._acknowledge, switch_profile.CFG_PATH, os.environ.get("COWRIE_LISTEN_ADDR"))
    try:
        cfg = tmp / "cowrie.cfg"
        marker = tmp / "restart.marker"
        os.environ["COWRIE_LISTEN_ADDR"] = "127.0.0.1"
        switch_profile.CFG_PATH = cfg
        switch_profile.generate_config("centos_7")
        before = cfg.read_text(encoding="utf-8")
        cowrie = FakeCowrie(cfg, marker, mode)
        # restart command: create the marker (the fake Cowrie "restarts"), then exit with the scenario's code
        restart_cmd = (f'"{sys.executable}" -c "import pathlib,sys; pathlib.Path(r\'{marker}\').touch(); '
                       f'sys.exit({exit_code})"')
        persona_fs = tmp / "personas"
        persona_fs.mkdir()
        for p in switch_profile.PROFILES:
            (persona_fs / f"{p}.pickle").write_bytes(b"rehearsal")
        os.environ["COWRIE_PERSONA_FS"] = str(persona_fs)
        backend = FakeBackend("centos_7", nxt)
        _patch_backend_calls(backend)
        t0 = time.monotonic()
        result = rot.rotate_once(backend, cfg, restart_cmd, dry_run=False, force=False, verify=True,
                                 verify_addr=("127.0.0.1", cowrie.port), verify_timeout=verify_timeout)
        after = cfg.read_text(encoding="utf-8")
        outcome = "APPLIED" if result.get("changed") else "FAILED"
        return {"scenario": name, "expected": expected, "outcome": outcome, "passed": outcome == expected and (
                    (outcome == "APPLIED" and backend.recorded == [nxt] and rot.served_persona(cfg) == nxt) or
                    (outcome == "FAILED" and after == before and backend.recorded == [] and len(backend.failed) == 1)),
                "cfgRestored": after == before, "recorded": backend.recorded, "failureReason": (backend.failed or [None])[0],
                "restarts": cowrie.restarts, "seconds": round(time.monotonic() - t0, 2)}
    finally:
        if cowrie:
            cowrie.close()
        rot._fail, rot._acknowledge, switch_profile.CFG_PATH = saved[0], saved[1], saved[2]
        if saved[3] is None:
            os.environ.pop("COWRIE_LISTEN_ADDR", None)
        else:
            os.environ["COWRIE_LISTEN_ADDR"] = saved[3]
        os.environ.pop("COWRIE_PERSONA_FS", None)
        shutil.rmtree(tmp, ignore_errors=True)


def run_all(verify_timeout=2.0):
    results = [run_scenario(n, verify_timeout) for n in SCENARIOS]
    return {"kind": "ISOLATED rollback rehearsal (not the live honeypot)", "at": datetime.now(timezone.utc).isoformat(),
            "passed": all(r["passed"] for r in results), "results": results}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--verify-timeout", type=float, default=2.0)
    a = ap.parse_args()
    rep = run_all(a.verify_timeout)
    text = json.dumps(rep, indent=1)
    if a.json:
        Path(a.json).write_text(text, encoding="utf-8")
    print(text)
    return 0 if rep["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
