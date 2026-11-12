"""
Persona policy v2: a discounted-UCB persona bandit with a weak synthetic prior and a switching margin.

Why (see docs/PERSONA_POLICY_V2.md): the v1 tabular Q-learner starts from 12,087 synthetic episodes whose values
(~136) are ~4x what real rewards (mean ~3.4) can sustain, its epsilon counts those episodes (already at its 0.05
floor), and its state is only the previous persona, so its picks barely depend on what attackers do.

v2 treats persona choice as what it is, a bandit over the servable personas:
  * Per persona, a discounted count N and discounted reward sum S of real sessions (rewards normalised to [0, 1]
    with deception_scorer's own reward bounds). Every real observation multiplies all N, S by `discount` before
    adding itself, so old evidence fades and a change in attacker behaviour can be followed (D-UCB).
  * The synthetic seed is only a prior: `prior_weight` pseudo-sessions per persona at the seed's implied mean,
    decaying like real data. 12,087 synthetic episodes therefore weigh as much as `prior_weight` real sessions.
  * Exploration is counted from real sessions only: index = mean + c * sqrt(ln(sum N) / N).
  * Switching costs a Cowrie restart (dropped sessions): the current persona is kept unless another persona's
    index beats it by `switch_margin`.
It never applies anything: the rotator applies recommendations, exactly as for v1. Its state lives in its own file
(never the v1 Q-table), stamped with POLICY_VERSION, and each session is learned at most once (session-id dedupe).
"""
import json, logging, math, os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from rl_engine.deception_scorer import (
    PROFILES_LIST, REWARD_MAX, REWARD_MIN, _exclusive_lock, _replace_with_retry, servable_profiles,
)

log = logging.getLogger("sentinel.rl.v2")

POLICY_VERSION = "persona-ducb-v2"
# Tuned on simulation seeds 0-9 and evaluated on held-out seeds 100-129 by evaluation/persona_policy_sim.py
# (SIMULATED attacker; see docs/PERSONA_POLICY_V2.md). Change them only together with a re-run of that script.
DEFAULTS = {"discount": 0.99, "exploration": 0.15, "switch_margin": 0.04, "prior_weight": 1.0}
SEEN_LIMIT = 2000
MODELS_DIR = (Path(__file__).resolve().parent.parent / "models").resolve()


def normalise(reward: float) -> float:
    return min(1.0, max(0.0, (float(reward) - REWARD_MIN) / (REWARD_MAX - REWARD_MIN)))


def prior_from_q_table(q_table: dict, gamma: float = 0.9) -> dict:
    """Implied mean reward per persona from a v1 Q-table: Q ~ r / (1 - gamma) at a fixed point, averaged over states.
    Only the *relative* preference survives normalisation; its weight is set separately (prior_weight)."""
    means = {}
    for a in PROFILES_LIST:
        vals = [row.get(a, 0.0) for row in (q_table or {}).values() if isinstance(row, dict)]
        means[a] = normalise((1 - gamma) * (sum(vals) / len(vals))) if vals else 0.5
    return means


class PersonaPolicyV2:
    def __init__(self, state_path, prior_means=None, prior_source="none", prior_episodes=0, **params):
        self.state_path = Path(state_path)
        if self.state_path.resolve() == MODELS_DIR or MODELS_DIR in self.state_path.resolve().parents:
            raise PermissionError(f"v2 policy state may not live in the protected models directory ({self.state_path})")
        self.params = {**DEFAULTS, **{k: float(v) for k, v in params.items() if v is not None}}
        self.prior = {"source": prior_source, "syntheticEpisodesRepresented": int(prior_episodes),
                      "weight": self.params["prior_weight"],
                      "means": {a: round(float((prior_means or {}).get(a, 0.5)), 6) for a in PROFILES_LIST}}
        self.arms = {a: {"n": self.params["prior_weight"], "s": self.params["prior_weight"] * self.prior["means"][a]}
                     for a in PROFILES_LIST}
        self.real_episodes = 0
        self.seen = deque(maxlen=SEEN_LIMIT)
        self.created_at = datetime.now(timezone.utc).isoformat()
        self._load()

    # ── persistence (own file, atomic, cross-process lock) ─────────────────────────────────────────────────────
    def _quarantine(self, reason: str):
        """Move an unusable state file aside (never delete or overwrite it): <name>.<reason>-<UTC timestamp>."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = self.state_path.with_name(f"{self.state_path.name}.{reason}-{stamp}")
        n = 1
        while target.exists():
            target = self.state_path.with_name(f"{self.state_path.name}.{reason}-{stamp}-{n}"); n += 1
        try:
            os.replace(self.state_path, target)
            log.warning("v2 policy state %s is %s: kept as %s; starting from the prior", self.state_path, reason, target.name)
            self.quarantined = str(target)
        except OSError as e:
            # Could not move it: refuse to run rather than overwrite it on the next save.
            raise RuntimeError(f"v2 policy state {self.state_path} is {reason} and could not be moved aside ({e})") from e

    def _load(self):
        self.quarantined = None
        if not self.state_path.exists():
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._quarantine("corrupt")
            return
        if not isinstance(data, dict) or data.get("policyVersion") != POLICY_VERSION:
            self._quarantine("incompatible")
            return
        try:
            params = {k: float(v) for k, v in (data.get("params") or {}).items() if k in DEFAULTS}
            arms = {}
            for a, st in (data.get("arms") or {}).items():
                if a in self.arms:
                    n, s = float(st["n"]), float(st["s"])
                    if not (math.isfinite(n) and math.isfinite(s) and n >= 0 and 0 <= s <= n + 1e-9):
                        raise ValueError(f"arm {a} out of range")
                    arms[a] = {"n": n, "s": s}
            real = int(data.get("realEpisodes", 0))
            seen = data.get("seenSessionIds", [])
            if real < 0 or not isinstance(seen, list) or not all(isinstance(x, str) for x in seen):
                raise ValueError("episode accounting malformed")
        except (KeyError, TypeError, ValueError, AttributeError):
            self._quarantine("corrupt")
            return
        self.params = {**self.params, **params}
        self.prior = data.get("prior", self.prior)
        self.arms.update(arms)
        self.real_episodes = real
        self.seen = deque(seen[-SEEN_LIMIT:], maxlen=SEEN_LIMIT)
        self.created_at = data.get("createdAt", self.created_at)

    def save(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"policyVersion": POLICY_VERSION, "createdAt": self.created_at,
                   "savedAt": datetime.now(timezone.utc).isoformat(), "params": self.params, "prior": self.prior,
                   "realEpisodes": self.real_episodes, "arms": self.arms, "seenSessionIds": list(self.seen)}
        with _exclusive_lock(self.state_path):
            tmp = self.state_path.with_suffix(f".tmp_{os.getpid()}")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            _replace_with_retry(tmp, self.state_path)

    # ── learning ───────────────────────────────────────────────────────────────────────────────────────────────
    def observe(self, session_id, persona, reward, persist=True) -> bool:
        """Learn from one real scored session. False (nothing learned) for a session already learned or an unknown
        persona. Discounting runs per observation, so it measures 'sessions ago', not wall-clock time."""
        sid = str(session_id or "").strip()
        # No id, no exactly-once guarantee: such an observation is never learned (it could not be deduplicated).
        if not sid or persona not in self.arms or sid in self.seen:
            return False
        g = self.params["discount"]
        for st in self.arms.values():
            st["n"] *= g
            st["s"] *= g
        self.arms[persona]["n"] += 1.0
        self.arms[persona]["s"] += normalise(reward)
        self.real_episodes += 1
        if sid:
            self.seen.append(sid)
        if persist:
            self.save()
        return True

    # ── recommending ───────────────────────────────────────────────────────────────────────────────────────────
    def mean(self, a):
        st = self.arms[a]
        return st["s"] / st["n"] if st["n"] > 1e-12 else 0.0

    def indices(self, actions=None):
        actions = actions or servable_profiles()
        total = max(sum(self.arms[a]["n"] for a in actions), math.e)
        c = self.params["exploration"]
        return {a: (math.inf if self.arms[a]["n"] <= 1e-9 else
                    self.mean(a) + c * math.sqrt(math.log(total) / self.arms[a]["n"])) for a in actions}

    def greedy(self, actions=None):
        actions = actions or servable_profiles()
        return max(actions, key=self.mean)

    def recommend(self, current=None):
        """Next persona to serve. Keeps `current` unless another persona's index beats it by switch_margin.
        Deterministic: ties break by the persona list order."""
        actions = servable_profiles()
        idx = self.indices(actions)
        best = max(actions, key=lambda a: idx[a])
        if current in idx and idx[best] - idx[current] < self.params["switch_margin"]:
            return current
        return best

    def stats(self, current=None):
        actions = servable_profiles()
        idx = self.indices(actions)
        rec = self.recommend(current)
        return {"policyVersion": POLICY_VERSION, "realEpisodes": self.real_episodes, "params": self.params,
                "prior": {k: self.prior[k] for k in ("source", "syntheticEpisodesRepresented", "weight")},
                # exploration = recommending neither the best-known persona nor the one already served
                "recommendation": rec, "explored": rec != self.greedy(actions) and rec != current,
                "arms": {a: {"effectiveSessions": round(self.arms[a]["n"], 3), "meanNormalisedReward": round(self.mean(a), 4),
                             "index": (None if math.isinf(idx[a]) else round(idx[a], 4))} for a in actions}}
