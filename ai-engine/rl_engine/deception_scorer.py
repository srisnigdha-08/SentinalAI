#!/usr/bin/env python3
"""
SentinelAI Q-Learning Deception Engine
Adapts honeypot OS profile based on attacker engagement.
Run demo: python deception_scorer.py
"""
import json, math, random, logging, os, sys, tempfile, secrets
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
    3. In all other cases (unconfigured scripts, test runners, diagnostics, ad-hoc runs),
       safely redirect to an isolated, process-specific temporary directory.
    """
    env_path = os.getenv("DEFAULT_RUNTIME_Q_TABLE_PATH")
    if env_path:
        return Path(env_path).resolve()

    if is_repo_runtime_write_authorized() and not is_test_or_diagnostic_mode():
        return (Path(__file__).parent.parent / "runtime" / "q_table.json").resolve()

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

def calc_reward(session: dict) -> float:
    r = 0.0
    dur = session.get("durationSeconds", 0)
    if dur > 0: r += math.log1p(dur / 60.0) * 2.0
    cmds = session.get("commands", [])
    r += len(cmds) * 0.3
    for cmd in cmds: r += INTENT_BONUSES.get(cmd.get("intent",""), 0)
    r += session.get("iocCount", 0) * 0.5
    if session.get("loginSucceeded", False): r += 2.0
    return min(r, 20.0)

class DeceptionQLearner:
    def __init__(self, alpha=0.1, gamma=0.9, epsilon=0.2, q_table_path="rl_engine/q_table.json"):
        self.alpha=alpha; self.gamma=gamma; self.epsilon=epsilon; self.q_table_path=q_table_path
        self.episode_count=0; self.total_reward=0.0; self.reward_history=[]
        self.q_table={s:{a:0.0 for a in PROFILES_LIST} for s in PROFILES_LIST}
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
            except: pass

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
        # Atomic persistence: write to sibling temporary file and atomically replace.
        # This prevents 0-byte truncation or partial JSON corruption if interrupted.
        tmp_id = f"{os.getpid()}_{secrets.token_hex(4)}"
        tmp_target = target.with_suffix(f".tmp_{tmp_id}")
        payload = {
            "q_table": self.q_table,
            "episode_count": self.episode_count,
            "total_reward": round(self.total_reward, 2),
            "reward_history": self.reward_history[-100:],
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
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

    def choose_action(self, state: str) -> str:
        eps=self.epsilon/(1+self.episode_count*0.01)
        if random.random()<eps: return random.choice(PROFILES_LIST)
        q=self.q_table.get(state,{}); return max(q,key=q.get)

    def update(self, state, action, reward, next_state):
        cur=self.q_table[state][action]
        max_n=max(self.q_table.get(next_state,{}).values(),default=0.0)
        self.q_table[state][action]=round(cur+self.alpha*(reward+self.gamma*max_n-cur),4)
        self.episode_count+=1; self.total_reward+=reward; self.reward_history.append(round(reward,2))
        if self.episode_count%10==0: self.save()

    def get_profile_rankings(self):
        avg={p:sum(self.q_table[s].get(p,0) for s in PROFILES_LIST)/len(PROFILES_LIST) for p in PROFILES_LIST}
        return sorted([{"profile":p,"avgQ":round(q,3),"config":PROFILES[p]} for p,q in avg.items()],key=lambda x:x["avgQ"],reverse=True)

    def get_stats(self):
        recent=self.reward_history[-20:]
        return {"episodeCount":self.episode_count,"totalReward":round(self.total_reward,2),"avgRecentReward":round(sum(recent)/len(recent),2) if recent else 0,"epsilon":round(self.epsilon/(1+self.episode_count*0.01),3),"profileRankings":self.get_profile_rankings()}

class SessionScorer:
    def __init__(self, q_table_path="rl_engine/q_table.json"):
        self.learner=DeceptionQLearner(q_table_path=q_table_path); self.current="ubuntu_22"

    def process_session(self, session: dict) -> dict:
        reward=calc_reward(session); prev=session.get("deceptionProfile",self.current)
        next_p=self.learner.choose_action(prev); self.learner.update(prev,next_p,reward,next_p)
        self.current=next_p
        return {"sessionId":session.get("sessionId"),"deceptionScore":round(min(reward*5,100),1),"rawReward":round(reward,3),"prevProfile":prev,"nextProfile":next_p,"nextConfig":PROFILES[next_p],"learnerStats":self.learner.get_stats()}

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
