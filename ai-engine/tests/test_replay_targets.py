"""demo/replay_cicids.py targets: the backend driver signs in with the CSRF handshake, sends flows to
/api/ai/analyze, re-logs in once on 401, uses TEST-NET-2 addresses, and never sends the label."""
import importlib.util
import ipaddress
from pathlib import Path

import pandas as pd
import pytest

_spec = importlib.util.spec_from_file_location(
    "replay_cicids", Path(__file__).resolve().parent.parent / "demo" / "replay_cicids.py")
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)
replay.disable_colors()


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise replay.requests.exceptions.HTTPError(str(self.status_code))


class FakeSession:
    """Records calls; serves CSRF, login (token-1, token-2, ...) and analyze responses."""
    def __init__(self, analyze_statuses=(200,)):
        self.calls = []
        self.logins = 0
        self.analyze_statuses = list(analyze_statuses)

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("GET", url, headers, None))
        if url.endswith("/api/auth/csrf"):
            return FakeResponse(200, {"data": {"csrfToken": "nonce.sig"}})
        if url.endswith("/api/auth/me"):
            return FakeResponse(200, {"data": {"user": {"role": "analyst"}}})
        if url.endswith("/api/threats/settings"):
            return FakeResponse(200, {"data": {"autoBlockEnabled": False}})
        return FakeResponse(404, {})

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append(("POST", url, headers, json))
        if url.endswith("/api/auth/login"):
            self.logins += 1
            return FakeResponse(200, {"data": {"token": f"token-{self.logins}"}})
        if url.endswith("/api/ai/analyze"):
            status = self.analyze_statuses.pop(0) if self.analyze_statuses else 200
            if status != 200:
                return FakeResponse(status, {"success": False})
            return FakeResponse(200, {"data": {"result": {"predictedClass": "DDoS", "threatScore": 0.97,
                                                          "action": "BLOCK", "_id": "pred-1"}}})
        return FakeResponse(404, {})


def make_target(session):
    target = replay.BackendTarget("http://127.0.0.1:5000/", "analyst@example.test", "pw-not-logged", "http://localhost:3000")
    target.http = session
    return target


def test_login_uses_csrf_handshake_and_origin():
    session = FakeSession()
    target = make_target(session)
    target.login()

    method, url, headers, _ = session.calls[0]
    assert (method, url) == ("GET", "http://127.0.0.1:5000/api/auth/csrf")
    assert headers["Origin"] == "http://localhost:3000"
    method, url, headers, body = session.calls[1]
    assert (method, url) == ("POST", "http://127.0.0.1:5000/api/auth/login")
    assert headers["X-CSRF-Token"] == "nonce.sig" and headers["Origin"] == "http://localhost:3000"
    assert body == {"email": "analyst@example.test", "password": "pw-not-logged"}
    assert target.token == "token-1"
    assert all("pw-not-logged" not in url for _, url, _, _ in session.calls)


def test_analyze_posts_bearer_token_and_relogs_once_on_401():
    session = FakeSession(analyze_statuses=[401, 200])
    target = make_target(session)
    target.login()
    resp = target.analyze({"flow_duration": 1.0, "sourceIP": target.source_ip(1)})

    assert resp.status_code == 200
    analyze_calls = [c for c in session.calls if c[1].endswith("/api/ai/analyze")]
    assert [c[2]["Authorization"] for c in analyze_calls] == ["Bearer token-1", "Bearer token-2"]
    assert target.result_of(resp.json())["predictedClass"] == "DDoS"


def test_backend_source_ips_are_test_net_2_only():
    target = make_target(FakeSession())
    net = ipaddress.ip_network("198.51.100.0/24")
    assert all(ipaddress.ip_address(target.source_ip(i)) in net for i in range(1, 600))


def test_login_failure_reports_status_without_password():
    class Rejecting(FakeSession):
        def post(self, url, json=None, headers=None, timeout=None):
            return FakeResponse(401, {"error": "Invalid credentials"})
    target = make_target(Rejecting())
    with pytest.raises(RuntimeError) as exc:
        target.login()
    assert "401" in str(exc.value) and "pw-not-logged" not in str(exc.value)


def test_run_replay_through_backend_never_sends_label(tmp_path):
    cols = list(replay.HEADER_TO_RECORD_FIELD.keys())
    rows = []
    for label in ["BENIGN", "BENIGN"] + ["DDoS"] * 25:
        rows.append({**{c: 1.0 for c in cols}, "Label": label})
    csv = tmp_path / "Friday-sample.csv"
    pd.DataFrame(rows).to_csv(csv, index=False)

    session = FakeSession()
    target = make_target(session)
    target.login()
    summary = replay.run_replay(str(csv), total_rows=4, delay=0, target=target)

    sent = [c[3] for c in session.calls if c[1].endswith("/api/ai/analyze")]
    assert len(sent) == 4
    assert all("Label" not in p and "label" not in p for p in sent)
    assert all(ipaddress.ip_address(p["sourceIP"]) in ipaddress.ip_network("198.51.100.0/24") for p in sent)
    assert summary == {"evaluated": 4, "correct": 2, "failed": 0}


def test_engine_target_still_uses_side_effect_free_eval():
    target = replay.EngineTarget("http://localhost:8000/", "k")
    assert target.describe() == "http://localhost:8000/predict/eval"
    assert target.result_of({"result": {"predictedClass": "BENIGN"}}) == {"predictedClass": "BENIGN"}
