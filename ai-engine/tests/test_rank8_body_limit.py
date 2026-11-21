"""Rank 8: the AI engine's 2 MB request-body limit is enforced on the bytes actually received.

The old check trusted Content-Length only, so a chunked body, a false small Content-Length or a malformed header
passed. Exercised at the ASGI level (exact framing control) and through the real application.
"""
import asyncio
import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
with patch("inference.predictor.SentinelPredictor.load"), patch("inference.predictor.SentinelPredictor.init_explainer"), \
     patch("joblib.load", return_value=MagicMock()):
    import inference.main as main  # noqa: E402

LIMIT = main.MAX_REQUEST_BODY_BYTES
assert LIMIT == main.MAX_HONEYPOT_SESSION_BYTES == 2_000_000


def run(path, chunks, headers=(), method="POST"):
    """Drive BodySizeLimit with the given body chunks. Returns (status, app_body_or_None, chunks_read)."""
    seen = {"body": None}

    async def app(scope, receive, send):
        body = b""
        while True:
            m = await receive()
            body += m.get("body", b"")
            if not m.get("more_body"):
                break
        seen["body"] = body
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    reads = {"n": 0}
    queue = list(chunks)

    async def receive():
        reads["n"] += 1
        if not queue:
            return {"type": "http.request", "body": b"", "more_body": False}
        body = queue.pop(0)
        return {"type": "http.request", "body": body, "more_body": bool(queue)}

    out = {}

    async def send(m):
        if m["type"] == "http.response.start":
            out["status"] = m["status"]

    scope = {"type": "http", "method": method, "path": path,
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers]}
    asyncio.run(main.BodySizeLimit(app)(scope, receive, send))
    return out["status"], seen["body"], reads["n"]


MB = 1024 * 1024


@pytest.mark.parametrize("path", ["/predict/honeypot", "/predict/honeypot/internal", "/deception/score", "/predict",
                                  "/predict/batch", "/explain/vector", "/predict/auth/shadow"])
def test_bodies_within_the_limit_pass_unchanged(path):
    body = b"x" * (LIMIT - 10)
    status, got, _ = run(path, [body[:500_000], body[500_000:]], [("content-length", str(len(body)))])
    assert status == 200 and got == body


@pytest.mark.parametrize("path", ["/predict/honeypot/internal", "/deception/score", "/predict/batch", "/predict"])
def test_a_declared_length_over_the_limit_is_refused_before_reading(path):
    status, got, reads = run(path, [b"x" * 10], [("content-length", str(LIMIT + 1))])
    assert status == 413 and got is None and reads == 0


def test_missing_content_length_and_chunked_bodies_are_counted():
    status, got, reads = run("/predict/honeypot/internal", [b"y" * MB] * 3)  # no Content-Length (chunked)
    assert status == 413 and got is None and reads == 2  # stops as soon as the count passes the limit
    status, got, _ = run("/predict/honeypot/internal", [b"y" * 1000] * 5, [("transfer-encoding", "chunked")])
    assert status == 200 and len(got) == 5000


def test_a_false_small_content_length_does_not_bypass_the_limit():
    status, got, reads = run("/deception/score", [b"z" * MB] * 4, [("content-length", "10")])
    assert status == 413 and got is None and reads <= 3


@pytest.mark.parametrize("value", ["abc", "-1", "1e9", "", " ", "2000000.5", "0x10"])
def test_malformed_content_length_is_refused(value):
    status, got, _ = run("/predict", [b"{}"], [("content-length", value)])
    assert status == 400 and got is None


def test_conflicting_duplicate_content_lengths_are_refused():
    status, _, _ = run("/predict", [b"{}"], [("content-length", "2"), ("content-length", "5000000")])
    assert status == 400


def test_multibyte_utf8_is_counted_in_bytes_not_characters():
    text = ("é" * (LIMIT // 2 + 10)).encode("utf-8")  # fewer characters than the limit, more bytes
    assert len(text) > LIMIT and len(text.decode()) < LIMIT
    status, _, _ = run("/predict/honeypot", [text])
    assert status == 413


def test_an_excessive_stream_is_not_read_to_the_end():
    status, _, reads = run("/predict", [b"a" * 512 * 1024] * 400)  # ~200 MB offered
    assert status == 413 and reads <= 5


def test_get_requests_are_unaffected():
    status, _, _ = run("/health", [], method="GET")
    assert status == 200


def test_through_the_application(monkeypatch):
    from fastapi.testclient import TestClient
    with patch("inference.main._notify"), patch("inference.predictor.SentinelPredictor.get_model_info", return_value={"v": 1}), \
         TestClient(main.app) as client:
        h = {"X-API-Key": os.environ["SENTINEL_KEY"]}
        big = {"sessionId": "s", "sourceIP": "198.51.100.1", "commands": [{"command": "x" * (LIMIT + 10)}]}
        r = client.post("/predict/honeypot/internal", json=big, headers=h)
        assert r.status_code == 413 and r.json()["detail"]["error"] == "SESSION_TOO_LARGE"
        r = client.post("/deception/score", json=big, headers=h)
        assert r.status_code == 413
        def gen():
            for _ in range(3):
                yield b"q" * MB
        r = client.post("/predict", content=gen(), headers={**h, "content-type": "application/json"})
        assert r.status_code == 413 and r.json()["detail"]["error"] == "REQUEST_TOO_LARGE"
        r = client.post("/explain/vector", json={"featureVector": [0.0] * 53, "featureSchemaVersion": "x"}, headers=h)
        assert r.status_code != 413
