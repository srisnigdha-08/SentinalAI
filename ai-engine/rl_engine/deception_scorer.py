#!/usr/bin/env python3
"""
SentinelAI Q-Learning Deception Engine
Adapts honeypot OS profile based on attacker engagement.
Run demo: python deception_scorer.py
"""
import json, math, random, logging, os, re, sys, tempfile, secrets, time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.rl")

def is_test_or_diagnostic_mode() -> bool:
    """
    Determine whether execution is taking place under a test runner, test script,
    or diagnostic/verification environment.
    """
    if any(os.getenv(v) for v in ("PYTEST_CURRENT_TEST", "SENTINEL_TEST_MODE", "SENTINEL_DIAGNOSTIC")):
        return True
    if os.getenv("SENTINEL_ENV", "").lower() in ("test", "testing", "diagnostic", "verification"):
        return True
    if os.getenv("NODE_ENV", "").lower() in ("test", "testing"):
        return True
    if "pytest" in sys.modules:
        return True
    if getattr(sys, "argv", None):
        arg0 = sys.argv[0] if sys.argv else ""
        if arg0:
            arg0_path = Path(arg0)
            name_lower = arg0_path.name.lower()
            if name_lower.startswith("test_") or name_lower.endswith("_test.py") or "pytest" in name_lower:
                return True
            if any(part.lower() in ("tests", "test") for part in arg0_path.parts):
                return True
            if any(diag in name_lower for diag in ("diagnostic", "readiness", "benchmark", "dry_run")):
                return True
    return False

def is_repo_runtime_write_authorized() -> bool:
    """
    Writing to the repository runtime Q-table requires explicit, intentional configuration.
    Heuristic detection that a script 'is not a test' is NOT sufficient to grant repository write access.
    """
    return os.getenv("SENTINEL_ALLOW_REPO_RUNTIME_WRITE", "").lower() in ("1", "true", "yes")

def get_default_runtime_path() -> Path:
    """
    Return the approved runtime Q-table path.
    1. If an explicit DEFAULT_RUNTIME_Q_TABLE_PATH is provided, use it (custom/test path).
    2. If repository runtime write is explicitly authorized (SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1)
       and not running in test/diagnostic mode, resolve to the repository runtime directory.
    3. Test runners and diagnostics redirect to an isolated, process-specific temporary directory.
    4. A normal service run without either flag persists to a stable per-user directory outside the
       repository, so learning survives restarts instead of being discarded with a per-PID temp dir.
    """
    env_path = os.getenv("DEFAULT_RUNTIME_Q_TABLE_PATH")
    if env_path:
        return Path(env_path).resolve()

    if is_repo_runtime_write_authorized() and not is_test_or_diagnostic_mode():
        return (Path(__file__).parent.parent / "runtime" / "q_table.json").resolve()

    if not is_test_or_diagnostic_mode():
        base = Path(os.getenv("LOCALAPPDATA") or Path.home() / ".local" / "share")
        return (base / "SentinelAI" / "runtime" / "q_table.json").resolve()

    # Default-deny on repo runtime: allocate a process-isolated temporary storage path
    temp_dir = Path(tempfile.gettempdir()) / f"sentinelai_isolated_runtime_{os.getpid()}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return (temp_dir / "q_table.json").resolve()

PROFILES = {
    "ubuntu_22":    {"os":"Ubuntu 22.04 LTS","kernel":"Linux 5.15.0-91-generic","prompt":"root@ubuntu-srv:~#","banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6","ports":[22,80,443,3306]},
    "debian_11":    {"os":"Debian GNU/Linux 11","kernel":"Linux 5.10.0-27-amd64","prompt":"root@debian-prod:~#","banner":"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3","ports":[22,80,8080,5432]},
    "centos_7":     {"os":"CentOS Linux 7","kernel":"Linux 3.10.0-1160.el7.x86_64","prompt":"[root@centos-web ~]#","banner":"SSH-2.0-OpenSSH_7.4","ports":[22,80,443,3306]},
    "windows_srv":  {"os":"Windows Server 2019","kernel":"NT 10.0 Build 17763","prompt":"C:\\Users\\Administrator>","banner":"SSH-2.0-OpenSSH_for_Windows_8.1","ports":[22,80,443,3389]},
    "aws_ec2":      {"os":"Amazon Linux 2","kernel":"Linux 5.10.198-187.amzn2.x86_64","prompt":"[ec2-user@ip-10-0-1-42 ~]$","banner":"SSH-2.0-OpenSSH_7.4","ports":[22,80,443,8080]},
    "raspberry_pi": {"os":"Raspbian GNU/Linux 11","kernel":"Linux 5.15.84-v8+","prompt":"pi@raspberrypi:~$","banner":"SSH-2.0-OpenSSH_8.4p1 Raspbian","ports":[22,8080]},
}
PROFILES_LIST = list(PROFILES.keys())

INTENT_BONUSES = {"CREDENTIAL_HARVEST":1.5,"MALWARE_DOWNLOAD":3.0,"REVERSE_SHELL":2.5,"PERSISTENCE":2.0,"PRIVILEGE_ESCALATION":1.5}

# Commands attackers run to tell a honeypot/VM from a real host. A persona that gets checked like this has
# been (or is about to be) identified, which the reward must penalise rather than count as engagement (H6).
FINGERPRINT_PATTERNS = [re.compile(p) for p in (
    r"\b(systemd-detect-virt|virt-what|dmidecode|imvirt)\b",
    r"/proc/1/(cgroup|sched|environ)",
    r"\bhypervisor\b",
    r"\bcowrie\b",
    r"/sys/class/dmi/id/",
)]
FINGERPRINT_PENALTY = 5.0
REWARD_MIN, REWARD_MAX = -10.0, 20.0


def is_fingerprint_command(command) -> bool:
    text = str(command or "").lower()
    return any(p.search(text) for p in FINGERPRINT_PATTERNS)


def calc_reward(session: dict) -> float:
    r = 0.0
    dur = session.get("durationSeconds", 0)
    if dur > 0: r += math.log1p(dur / 60.0) * 2.0
    cmds = session.get("commands", [])
    r += len(cmds) * 0.3
    for cmd in cmds: r += INTENT_BONUSES.get(cmd.get("intent",""), 0)
    r += session.get("iocCount", 0) * 0.5
    if session.get("loginSucceeded", False): r += 2.0
    if any(is_fingerprint_command(c.get("command")) for c in cmds): r -= FINGERPRINT_PENALTY
    return max(min(r, REWARD_MAX), REWARD_MIN)

# Exploration never decays below this, so a persona that looked bad early is still re-tried and a change in
# attacker behaviour can be noticed (rewards are non-stationary). The decayed value alone reached ~0.002.
EPSILON_MIN = 0.05
# Convergence signal: mean |TD error| over the last CONVERGENCE_WINDOW updates below CONVERGENCE_TOL reward
# units (2.5 % of the reward range's upper end) means the estimates have stopped moving.
CONVERGENCE_WINDOW = 100
CONVERGENCE_TOL = 0.5

# Recommendation policy (U6). The learner's "state" is only the previous persona, so the problem is close to a
# multi-armed bandit over personas. "ucb1" recommends by Upper Confidence Bound on each persona's mean
# (normalised) reward: unplayed personas first, then the best mean plus an exploration bonus that shrinks as
# a persona is tried more. "q_learning" (default) keeps the epsilon-greedy Q-table policy described in the paper.
# Per-persona arm statistics are maintained under both policies, so switching needs no relearning.
POLICY = os.getenv("DECEPTION_POLICY", "q_learning").strip().lower()
POLICIES = ("q_learning", "ucb1")
UCB_C = 1.0


def _normalised(reward: float) -> float:
    return (reward - REWARD_MIN) / (REWARD_MAX - REWARD_MIN)


LOCK_TIMEOUT_S = 5.0
LOCK_STALE_S = 30.0


def _file_signature(path: Path):
    try:
        st = path.stat()
        return (str(path.resolve()), st.st_mtime_ns, st.st_size)
    except OSError:
        return None


@contextmanager
def _exclusive_lock(target: Path):
    """Cross-process lock via an O_EXCL sibling file; a lock older than LOCK_STALE_S is treated as abandoned."""
    lock = target.with_name(target.name + ".lock")
    deadline = time.monotonic() + LOCK_TIMEOUT_S
    while True:
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > LOCK_STALE_S:
                    lock.unlink()
                    continue
            except OSError:
                continue
            if time.monotonic() > deadline:
                raise TimeoutError(f"Q-table lock busy: {lock}")
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            lock.unlink()
        except OSError:
            pass


class DeceptionQLearner:
    def __init__(self, alpha=0.1, gamma=0.9, epsilon=0.2, q_table_path="rl_engine/q_table.json"):
        self.alpha=alpha; self.gamma=gamma; self.epsilon=epsilon; self.q_table_path=q_table_path
        self.episode_count=0; self.total_reward=0.0; self.reward_history=[]; self.td_errors=[]
        self.policy = POLICY if POLICY in POLICIES else "q_learning"
        self.arm_stats = {a: {"n": 0, "mean": 0.0} for a in PROFILES_LIST}
        self.q_table={s:{a:0.0 for a in PROFILES_LIST} for s in PROFILES_LIST}
        # TD updates applied since the last save, and the state of the file when it was last read or written.
        # Together they let save() merge with another process's writes instead of overwriting them (M5).
        self._pending = []
        self._disk_signature = None
        # Where the table's starting values came from (written by inference.deception.get_scorer when it
        # copies the shipped seed); None for tables that predate the field.
        self.seed_provenance = None
        self._load()

    def _load(self):
        p=Path(self.q_table_path)
        if p.exists():
            try:
                with open(p) as f: data=json.load(f)
                self.q_table=data.get("q_table",self.q_table)
                self.episode_count=data.get("episode_count",0)
                self.total_reward=data.get("total_reward",0.0)
                self.reward_history=data.get("reward_history",[])
                self.td_errors=data.get("td_errors",[])
                for a, st in (data.get("arm_stats") or {}).items():
                    if a in self.arm_stats:
                        self.arm_stats[a] = {"n": int(st.get("n", 0)), "mean": float(st.get("mean", 0.0))}
                self.seed_provenance=data.get("seed_provenance")
                self._fill_missing(self.q_table)
                self._disk_signature=_file_signature(p)
            except (OSError, ValueError) as e:
                log.warning("Q-table at %s could not be read (%s); starting from defaults", p, type(e).__name__)

    @staticmethod
    def _fill_missing(table):
        """Every persona row and action present (0.0 when never updated), whatever the file on disk held."""
        for s_ in PROFILES_LIST:
            row = table.setdefault(s_, {})
            for a in PROFILES_LIST:
                row.setdefault(a, 0.0)
        return table

    def _td_update(self, table, state, action, reward, next_state):
        for s_ in (state, next_state):
            row = table.setdefault(s_, {})
            for a in PROFILES_LIST:
                row.setdefault(a, 0.0)
        cur = table[state][action]
        max_n = max(table.get(next_state, {}).values(), default=0.0)
        td_error = reward + self.gamma * max_n - cur
        table[state][action] = round(cur + self.alpha * td_error, 4)
        return abs(td_error)

    def _merge_foreign_writes(self, target: Path):
        """Another process saved since we last read/wrote: adopt its state, replay our pending updates."""
        with open(target, encoding="utf-8") as f:
            disk = json.load(f)
        table = disk.get("q_table", {})
        errors = [self._td_update(table, state, action, reward, next_state)
                  for state, action, reward, next_state in self._pending]
        self.td_errors = (disk.get("td_errors", []) + [round(e, 4) for e in errors])[-CONVERGENCE_WINDOW:]
        arms = {a: {"n": 0, "mean": 0.0} for a in PROFILES_LIST}
        for a, st in (disk.get("arm_stats") or {}).items():
            if a in arms:
                arms[a] = {"n": int(st.get("n", 0)), "mean": float(st.get("mean", 0.0))}
        self.arm_stats = arms
        for _, action, reward, _ in self._pending:
            self._record_arm(action, reward)
        self.q_table = self._fill_missing(table)
        self.seed_provenance = disk.get("seed_provenance", self.seed_provenance)
        self.episode_count = disk.get("episode_count", 0) + len(self._pending)
        self.total_reward = disk.get("total_reward", 0.0) + sum(r for _, _, r, _ in self._pending)
        self.reward_history = (disk.get("reward_history", []) + [round(r, 2) for _, _, r, _ in self._pending])[-100:]
        log.info("Q-table merged with another process's writes (%d pending updates replayed)", len(self._pending))

    def save(self):
        target = Path(self.q_table_path).resolve()
        models_dir = (Path(__file__).parent.parent / "models").resolve()
        models_baseline = (models_dir / "q_table.json").resolve()
        repo_runtime_dir = (Path(__file__).parent.parent / "runtime").resolve()
        repo_runtime_file = (repo_runtime_dir / "q_table.json").resolve()

        target_norm = os.path.normcase(str(target))
        baseline_norm = os.path.normcase(str(models_baseline))
        models_dir_norm = os.path.normcase(str(models_dir))
        runtime_dir_norm = os.path.normcase(str(repo_runtime_dir))
        runtime_file_norm = os.path.normcase(str(repo_runtime_file))

        is_models_target = (target_norm == baseline_norm or 
                            target_norm.startswith(models_dir_norm + os.sep) or 
                            target == models_baseline)

        # Rule 1: NEVER allow writes into models/ directory under ANY circumstance.
        if is_models_target:
            log.warning("Write targeting protected models directory (%s) blocked!", target)
            if is_test_or_diagnostic_mode() and not os.getenv("SENTINEL_FAIL_CLOSED_ON_REPO_MUTATION", "").lower() in ("1", "true", "yes"):
                target = get_default_runtime_path()
                self.q_table_path = str(target)
                target_norm = os.path.normcase(str(target))
            else:
                raise PermissionError(f"Write targeting protected models directory ({target}) blocked.")

        # Rule 2: Repository runtime requires explicit authorization (SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1).
        # Unflagged standalone scripts, inline one-liners, and test/diagnostic runs do not gain write access.
        is_repo_runtime_target = (target_norm == runtime_file_norm or 
                                  target_norm.startswith(runtime_dir_norm + os.sep) or 
                                  target == repo_runtime_file)

        if is_repo_runtime_target:
            if not is_repo_runtime_write_authorized():
                log.warning("Unauthorized write targeting repository runtime (%s) blocked!", target)
                if is_test_or_diagnostic_mode() and not os.getenv("SENTINEL_FAIL_CLOSED_ON_REPO_MUTATION", "").lower() in ("1", "true", "yes"):
                    temp_dir = Path(tempfile.gettempdir()) / f"sentinelai_isolated_runtime_{os.getpid()}"
                    temp_dir.mkdir(parents=True, exist_ok=True)
                    target = (temp_dir / "q_table.json").resolve()
                    self.q_table_path = str(target)
                else:
                    raise PermissionError(
                        f"Write targeting repository runtime ({target}) rejected: "
                        "Repository persistence requires explicit authorization via SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1."
                    )

        target.parent.mkdir(parents=True, exist_ok=True)
        with _exclusive_lock(target):
            current = _file_signature(target)
            if current is not None and current != self._disk_signature:
                try:
                    self._merge_foreign_writes(target)
                except (OSError, ValueError) as e:
                    log.warning("Q-table on disk unreadable during merge (%s); writing local state", type(e).__name__)
            # Atomic persistence: write to sibling temporary file and atomically replace.
            # This prevents 0-byte truncation or partial JSON corruption if interrupted.
            tmp_id = f"{os.getpid()}_{secrets.token_hex(4)}"
            tmp_target = target.with_suffix(f".tmp_{tmp_id}")
            payload = {
                "q_table": self.q_table,
                "episode_count": self.episode_count,
                "total_reward": round(self.total_reward, 2),
                "reward_history": self.reward_history[-100:],
                "td_errors": self.td_errors[-CONVERGENCE_WINDOW:],
                "arm_stats": self.arm_stats,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            if self.seed_provenance is not None:
                payload["seed_provenance"] = self.seed_provenance
            try:
                with open(tmp_target, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_target, target)
            except Exception:
                if tmp_target.exists():
                    try:
                        tmp_target.unlink()
                    except OSError:
                        pass
                raise
            self._disk_signature = _file_signature(target)
            self._pending = []

    def current_epsilon(self) -> float:
        return max(EPSILON_MIN, self.epsilon / (1 + self.episode_count * 0.01))

    def _record_arm(self, action, reward):
        st = self.arm_stats.setdefault(action, {"n": 0, "mean": 0.0})
        st["n"] += 1
        st["mean"] = round(st["mean"] + (_normalised(reward) - st["mean"]) / st["n"], 6)

    def ucb_scores(self) -> dict:
        total = sum(st["n"] for st in self.arm_stats.values())
        return {a: (float("inf") if st["n"] == 0 else
                    st["mean"] + UCB_C * math.sqrt(2 * math.log(max(total, 1)) / st["n"]))
                for a, st in self.arm_stats.items()}

    def greedy_action(self, state: str) -> str:
        """Best persona without exploration, under the active policy."""
        if self.policy == "ucb1":
            played = {a: st["mean"] for a, st in self.arm_stats.items() if st["n"] > 0}
            return max(played, key=played.get) if played else PROFILES_LIST[0]
        q = self.q_table.get(state, {})
        return max(q, key=q.get) if q else PROFILES_LIST[0]

    def choose_action(self, state: str) -> str:
        if self.policy == "ucb1":
            scores = self.ucb_scores()
            return max(PROFILES_LIST, key=lambda a: scores[a])  # list order breaks ties deterministically
        if random.random()<self.current_epsilon(): return random.choice(PROFILES_LIST)
        q=self.q_table.get(state,{}); return max(q,key=q.get)

    def update(self, state, action, reward, next_state):
        td_error = self._td_update(self.q_table, state, action, reward, next_state)
        self.td_errors = (self.td_errors + [round(td_error, 4)])[-CONVERGENCE_WINDOW:]
        self._pending.append((state, action, reward, next_state))
        self._record_arm(action, reward)
        self.episode_count+=1; self.total_reward+=reward; self.reward_history.append(round(reward,2))
        # Saving is atomic and the table is tiny, so persist every episode by default (Q_SAVE_EVERY to tune).
        if self.episode_count % max(1, int(os.getenv("Q_SAVE_EVERY", "1"))) == 0: self.save()

    def get_profile_rankings(self):
        avg={p:sum(self.q_table[s].get(p,0) for s in PROFILES_LIST)/len(PROFILES_LIST) for p in PROFILES_LIST}
        return sorted([{"profile":p,"avgQ":round(q,3),"config":PROFILES[p]} for p,q in avg.items()],key=lambda x:x["avgQ"],reverse=True)

    def convergence(self) -> dict:
        n = len(self.td_errors)
        mean = sum(self.td_errors) / n if n else None
        return {"window": CONVERGENCE_WINDOW, "updates": n, "meanAbsTdError": round(mean, 4) if mean is not None else None,
                "tolerance": CONVERGENCE_TOL, "converged": n >= CONVERGENCE_WINDOW and mean < CONVERGENCE_TOL}

    def provenance(self) -> dict:
        """
        How much of the table was learned from sessions scored here versus inherited from its starting seed.
        The shipped seed (models/q_table.json) is a synthetic warm start, not attacker data.
        """
        seed = self.seed_provenance
        if not seed:
            return {"seed": "unknown", "seedEpisodes": None, "sessionEpisodes": None, "synthetic": None}
        seed_n = int(seed.get("episodes", 0))
        return {"seed": seed.get("source", "unknown"), "seedEpisodes": seed_n,
                "sessionEpisodes": max(0, self.episode_count - seed_n), "synthetic": bool(seed.get("synthetic"))}

    def get_stats(self):
        recent=self.reward_history[-20:]
        return {"provenance":self.provenance(),"episodeCount":self.episode_count,"totalReward":round(self.total_reward,2),"avgRecentReward":round(sum(recent)/len(recent),2) if recent else 0,"epsilon":round(self.current_epsilon(),3),"epsilonMin":EPSILON_MIN,"convergence":self.convergence(),"policy":self.policy,
                "armStats":{a: {"n": st["n"], "meanNormalisedReward": round(st["mean"], 4)} for a, st in self.arm_stats.items()},"profileRankings":self.get_profile_rankings()}

class SessionScorer:
    """
    Credit assignment: the reward observed in a session belongs to the profile that was ACTIVE
    during that session (the action), taken from the state = the profile active before it.
    The returned nextProfile is only a recommendation; nothing here reconfigures Cowrie.
    """
    def __init__(self, q_table_path="rl_engine/q_table.json"):
        self.learner=DeceptionQLearner(q_table_path=q_table_path); self.current="ubuntu_22"
        self.last_active=None

    def process_session(self, session: dict) -> dict:
        reward=calc_reward(session)
        fingerprinted=any(is_fingerprint_command(c.get("command")) for c in session.get("commands", []))
        active=session.get("deceptionProfile")
        if active not in PROFILES: active=self.current
        state=session.get("previousProfile")
        if state not in PROFILES: state=self.last_active or active
        for s in (state, active):
            row=self.learner.q_table.setdefault(s,{})
            for a in PROFILES_LIST: row.setdefault(a,0.0)
        self.learner.update(state,active,reward,active)
        self.last_active=active; self.current=active
        next_p=self.learner.choose_action(active)
        return {"sessionId":session.get("sessionId"),"deceptionScore":round(min(reward*5,100),1),"rawReward":round(reward,3),"prevProfile":state,"activeProfile":active,"nextProfile":next_p,"nextConfig":PROFILES[next_p],"recommendationApplied":False,"fingerprintDetected":fingerprinted,"learnerStats":self.learner.get_stats()}

    def get_current_profile(self): return {"name":self.current,"config":PROFILES[self.current]}

if __name__=="__main__":
    print("SentinelAI RL Deception Engine Demo\n")
    scorer=SessionScorer(q_table_path="/tmp/test_q_table.json")
    sessions=[
        {"sessionId":"s1","durationSeconds":480,"loginSucceeded":True,"iocCount":3,"commands":[{"intent":"CREDENTIAL_HARVEST"},{"intent":"MALWARE_DOWNLOAD"},{"intent":"PERSISTENCE"}],"deceptionProfile":"ubuntu_22"},
        {"sessionId":"s2","durationSeconds":30,"loginSucceeded":False,"iocCount":0,"commands":[],"deceptionProfile":"ubuntu_22"},
        {"sessionId":"s3","durationSeconds":320,"loginSucceeded":True,"iocCount":2,"commands":[{"intent":"RECONNAISSANCE"},{"intent":"REVERSE_SHELL"}],"deceptionProfile":"debian_11"},
        {"sessionId":"s4","durationSeconds":720,"loginSucceeded":True,"iocCount":5,"commands":[{"intent":"CREDENTIAL_HARVEST"},{"intent":"MALWARE_DOWNLOAD"},{"intent":"MALWARE_DOWNLOAD"},{"intent":"PERSISTENCE"}],"deceptionProfile":"ubuntu_22"},
    ]
    print(f"{'Session':<10}{'Profile':<18}{'Duration':<12}{'Reward':<10}{'Score':<8}Next Profile")
    print("-"*68)
    for s in sessions:
        r=scorer.process_session(s)
        print(f"{s['sessionId']:<10}{s['deceptionProfile']:<18}{s['durationSeconds']}s{'':<8}{r['rawReward']:<10.2f}{r['deceptionScore']:<8}{r['nextProfile']}")
    print("\nProfile Rankings:")
    for p in scorer.learner.get_profile_rankings():
        bar="I"*max(0,int(p["avgQ"]*3))
        print(f"  {p['profile']:<18} Q={p['avgQ']:>6.3f}  {bar}")
    s=scorer.learner.get_stats()
    print(f"\nEpisodes: {s['episodeCount']} | Total Reward: {s['totalReward']} | Epsilon: {s['epsilon']}")
