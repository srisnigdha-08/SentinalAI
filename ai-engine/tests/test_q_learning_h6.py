"""H6: honeypot fingerprinting is penalised, exploration has a floor, and convergence is measured."""
import pytest

from rl_engine import deception_scorer as ds


def _session(commands, **extra):
    base = {"durationSeconds": 120, "loginSucceeded": True, "iocCount": 0, "deceptionProfile": "ubuntu_22",
            "commands": [{"command": c, "intent": "UNKNOWN"} for c in commands]}
    base.update(extra)
    return base


@pytest.mark.parametrize("cmd", ["systemd-detect-virt", "cat /proc/1/cgroup", "dmidecode -s system-product-name",
                                 "lscpu | grep -i hypervisor", "ls /opt/cowrie", "cat /sys/class/dmi/id/product_name"])
def test_fingerprint_commands_are_recognised(cmd):
    assert ds.is_fingerprint_command(cmd)


@pytest.mark.parametrize("cmd", ["ls -la", "uname -a", "cat /proc/cpuinfo", "wget http://x/y", "whoami"])
def test_ordinary_commands_are_not_fingerprinting(cmd):
    assert not ds.is_fingerprint_command(cmd)


def test_fingerprinting_lowers_the_reward_and_rewards_are_bounded():
    plain = ds.calc_reward(_session(["ls"]))
    probed = ds.calc_reward(_session(["ls", "systemd-detect-virt"]))
    assert probed == pytest.approx(plain + 0.3 - ds.FINGERPRINT_PENALTY)  # one more command, then the penalty
    assert ds.calc_reward(_session(["systemd-detect-virt"], durationSeconds=0, loginSucceeded=False)) < 0
    assert ds.calc_reward({"durationSeconds": 10 ** 9, "commands": [{"intent": "MALWARE_DOWNLOAD"}] * 50}) == ds.REWARD_MAX
    assert ds.REWARD_MIN <= ds.calc_reward(_session(["virt-what"], durationSeconds=0, loginSucceeded=False))


def test_exploration_never_falls_below_the_floor(tmp_path):
    learner = ds.DeceptionQLearner(q_table_path=str(tmp_path / "q.json"))
    learner.episode_count = 12087  # the shipped seed's count: the decayed value alone would be ~0.0016
    assert learner.current_epsilon() == ds.EPSILON_MIN
    assert learner.get_stats()["epsilon"] == ds.EPSILON_MIN
    learner.episode_count = 0
    assert learner.current_epsilon() == pytest.approx(learner.epsilon)


def test_convergence_is_reported_and_reached_on_a_stationary_reward(tmp_path, monkeypatch):
    monkeypatch.setenv("Q_SAVE_EVERY", "100000")
    learner = ds.DeceptionQLearner(q_table_path=str(tmp_path / "q.json"))
    assert learner.convergence()["converged"] is False and learner.convergence()["updates"] == 0
    for _ in range(50):
        learner.update("ubuntu_22", "centos_7", 10.0, "centos_7")
    early = learner.convergence()
    assert early["converged"] is False  # too few updates, and still moving
    for _ in range(1500):
        learner.update("centos_7", "centos_7", 10.0, "centos_7")
    late = learner.convergence()
    assert late["updates"] == ds.CONVERGENCE_WINDOW
    assert late["meanAbsTdError"] < ds.CONVERGENCE_TOL and late["converged"] is True
    assert learner.q_table["centos_7"]["centos_7"] == pytest.approx(10.0 / (1 - learner.gamma), rel=0.05)


def test_td_errors_survive_save_and_reload(tmp_path, monkeypatch):
    monkeypatch.setenv("Q_SAVE_EVERY", "1")
    monkeypatch.setenv("SENTINEL_ALLOW_REPO_RUNTIME_WRITE", "")
    path = tmp_path / "q.json"
    learner = ds.DeceptionQLearner(q_table_path=str(path))
    for _ in range(3):
        learner.update("ubuntu_22", "debian_11", 5.0, "debian_11")
    reloaded = ds.DeceptionQLearner(q_table_path=str(path))
    assert reloaded.td_errors == learner.td_errors and len(reloaded.td_errors) == 3


def test_scored_session_reports_fingerprinting(tmp_path):
    scorer = ds.SessionScorer(q_table_path=str(tmp_path / "q.json"))
    assert scorer.process_session(_session(["cat /proc/1/cgroup"]))["fingerprintDetected"] is True
    assert scorer.process_session(_session(["ls"]))["fingerprintDetected"] is False
