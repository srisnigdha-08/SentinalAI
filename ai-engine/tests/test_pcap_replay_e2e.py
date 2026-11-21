"""
Offline PCAP replay, end to end on the AI-engine side (docs/CAPTURE.md, "How it is verified").

PCAP file -> packet parsing -> flow extraction -> 53-feature contract -> AI-engine /predict/internal and /predict/eval.

Every fixture is a small synthetic pcap written into pytest's tmp_path; nothing touches a network interface, the
network or a capture driver. The deployed model (xgb_cicids_v1) is used read-only and only through the side-effect
free /predict/eval endpoint; the /predict/internal contract test uses a controlled stub predictor. No model, dataset
or Q-table is written.
"""
import ipaddress
import json
import math
import os
import struct
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")

from capture.flows import EMITTED_FEATURES, FlowExtractor  # noqa: E402
from capture.packets import (ACK, FIN, MAX_SNAPLEN, PSH, PROTO_TCP, RST, SYN, PcapError, build_tcp_frame,  # noqa: E402
                             build_udp_frame, parse_frame, write_pcap)
from capture.service import Health, main, run  # noqa: E402
from capture.sources import PcapReplaySource  # noqa: E402
from utils.features import FEATURE_NAMES, extract_features_from_record  # noqa: E402

A, B, C = "192.0.2.10", "198.51.100.20", "203.0.113.30"
T0 = 1_700_000_000.0
MARKER = b"SENTINEL-SECRET-PAYLOAD-7f3a"


# ── fixture builders ───────────────────────────────────────────────────────────────────────────────────────────────
def tcp_session(t0=T0, src=A, dst=B, sport=40000, dport=22):
    return [
        (t0 + 0.000, build_tcp_frame(src, dst, sport, dport, SYN, window=64240)),
        (t0 + 0.001, build_tcp_frame(dst, src, dport, sport, SYN | ACK, window=65160)),
        (t0 + 0.002, build_tcp_frame(src, dst, sport, dport, ACK)),
        (t0 + 0.010, build_tcp_frame(src, dst, sport, dport, PSH | ACK, payload_len=100)),
        (t0 + 0.020, build_tcp_frame(dst, src, dport, sport, PSH | ACK, payload_len=300)),
        (t0 + 0.030, build_tcp_frame(src, dst, sport, dport, FIN | ACK)),
        (t0 + 0.031, build_tcp_frame(dst, src, dport, sport, FIN | ACK)),
    ]


def udp_exchange(t0=T0 + 1, src=A, dst=C, sport=5353, dport=53):
    return [(t0, build_udp_frame(src, dst, sport, dport, 40)), (t0 + 0.005, build_udp_frame(dst, src, dport, sport, 120))]


def mixed_frames():
    arp = b"\xff" * 6 + b"\x00" * 6 + b"\x08\x06" + b"\x00" * 28
    icmp_ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 1, 0,
                          ipaddress.IPv4Address(A).packed, ipaddress.IPv4Address(B).packed) + b"\x08\x00" + b"\x00" * 6
    icmp = b"\x00" * 12 + b"\x08\x00" + icmp_ip
    return sorted(tcp_session() + udp_exchange() + [(T0 + 0.5, arp), (T0 + 0.6, icmp)])


def tcp_frame_with_payload(src, dst, sport, dport, flags, payload: bytes):
    """Like build_tcp_frame, but the payload is real bytes (to prove they are never kept)."""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 29200, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 0, 0, 64, PROTO_TCP, 0,
                     ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + payload


def write(tmp_path, frames, name="replay.pcap", linktype=1):
    p = tmp_path / name
    write_pcap(p, frames, linktype)
    return p


def replay(path):
    """The capture service path minus the network: returns (payloads, health, beats)."""
    posted, beats = [], []
    health = Health("pcap_replay", None)
    run(PcapReplaySource(str(path)), FlowExtractor(), posted.append, health, heartbeat=beats.append,
        heartbeat_seconds=0.0, max_flows_per_second=1e9)
    return posted, health, beats


def cli(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


# ── valid replay ───────────────────────────────────────────────────────────────────────────────────────────────────
def test_valid_pcap_extracts_tcp_and_udp_flows_with_the_feature_contract(tmp_path):
    posted, health, beats = replay(write(tmp_path, mixed_frames()))
    assert len(posted) == 2
    by_proto = {p["destinationIP"]: p for p in posted}
    tcp, udp = by_proto[B], by_proto[C]
    assert (tcp["sourceIP"], tcp["total_fwd_packets"], tcp["total_bwd_packets"]) == (A, 4, 3)
    assert (udp["sourceIP"], udp["total_fwd_packets"], udp["total_bwd_packets"]) == (A, 1, 1)
    assert udp["total_len_fwd_packets"] == 40 and udp["total_len_bwd_packets"] == 120
    assert udp["init_win_bytes_forward"] == -1 and udp["syn_flag_count"] == 0
    for p in posted:
        assert p["captureSource"] == "pcap_replay"
        assert set(p) == {"sourceIP", "destinationIP", "timestamp", "captureSource", *EMITTED_FEATURES}
        assert all(math.isfinite(p[k]) for k in EMITTED_FEATURES)
        assert p["timestamp"].endswith("Z")
    # 9 records: 7 TCP + 2 UDP parsed, ARP and ICMP skipped and counted
    assert health.counters["records"] == 11 and health.counters["skipped_frames"] == 2
    assert health.counters["packets"] == 9 and health.counters["posted"] == 2
    assert health.last_error is None
    assert beats[0]["status"] == "starting" and beats[-1]["status"] == "finished"
    assert all(b["mode"] == "pcap_replay" and b["interface"] is None for b in beats)


def test_replay_reproduces_the_fixture_the_backend_test_ingests(tmp_path):
    """backend/tests/pcapReplayIngest.test.js posts this fixture; it must stay the extractor's real output."""
    fixture = json.loads((Path(__file__).parent / "fixtures" / "pcap_replay_flows.json").read_text(encoding="utf-8"))
    posted, _, _ = replay(write(tmp_path, mixed_frames()))
    assert posted == fixture["flows"]


def test_every_payload_becomes_a_complete_53_vector(tmp_path):
    posted, _, _ = replay(write(tmp_path, mixed_frames()))
    for p in posted:
        vec = extract_features_from_record(p)
        assert len(vec) == len(FEATURE_NAMES) == 53
        for i, name in enumerate(FEATURE_NAMES):
            if name in EMITTED_FEATURES:
                assert vec[i] == pytest.approx(p[name]), name


@pytest.mark.parametrize("variant", ["ipv6", "vlan", "linux_sll", "raw_ip"])
def test_supported_link_and_network_variants(tmp_path, variant):
    eth_tcp = build_tcp_frame(A, B, 40000, 80, SYN, window=1000)
    if variant == "ipv6":
        src6, dst6 = ipaddress.IPv6Address("2001:db8::1").packed, ipaddress.IPv6Address("2001:db8::2").packed
        tcp = struct.pack("!HHIIBBHHH", 40000, 80, 0, 0, 5 << 4, SYN, 1000, 0, 0)
        frame, link = b"\x00" * 12 + b"\x86\xdd" + struct.pack("!IHBB", 6 << 28, len(tcp), PROTO_TCP, 64) + src6 + dst6 + tcp, 1
    elif variant == "vlan":
        frame, link = eth_tcp[:12] + b"\x81\x00\x00\x0a" + eth_tcp[12:], 1
    elif variant == "linux_sll":
        frame, link = b"\x00" * 14 + b"\x08\x00" + eth_tcp[14:], 113
    else:
        frame, link = eth_tcp[14:], 101
    posted, _, _ = replay(write(tmp_path, [(T0, frame)], linktype=link))
    assert len(posted) == 1 and posted[0]["destinationIP"] in (B, "2001:db8::2")
    assert posted[0]["init_win_bytes_forward"] == 1000


# ── provenance ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_cli_dry_run_labels_every_flow_pcap_replay_and_writes_finished_health(tmp_path, capsys):
    health_file = tmp_path / "health.json"
    code, out, err = cli(capsys, "--pcap", str(write(tmp_path, mixed_frames())), "--dry-run", "--health-file",
                         str(health_file))
    assert code == 0
    lines = [json.loads(line) for line in out.strip().splitlines()]
    assert len(lines) == 2 and {p["captureSource"] for p in lines} == {"pcap_replay"}
    snap = json.loads(health_file.read_text())
    assert snap["mode"] == "pcap_replay" and snap["status"] == "finished" and snap["interface"] is None
    assert not (tmp_path / "health.tmp").exists()  # atomic write leaves no temp file behind


# ── invalid input: clear errors, never silent ──────────────────────────────────────────────────────────────────────
def test_header_only_pcap_finishes_with_zero_flows_and_says_so(tmp_path, capsys):
    path = write(tmp_path, [])
    posted, health, beats = replay(path)
    assert posted == [] and beats[-1]["status"] == "finished"
    assert "no TCP/UDP packets found" in health.last_error and health.counters["records"] == 0
    code, out, _ = cli(capsys, "--pcap", str(path), "--dry-run")
    assert code == 0 and out.strip() == ""


def test_non_ip_only_pcap_reports_skipped_frames(tmp_path):
    arp = b"\xff" * 6 + b"\x00" * 6 + b"\x08\x06" + b"\x00" * 28
    posted, health, _ = replay(write(tmp_path, [(T0, arp), (T0 + 1, arp)]))
    assert posted == [] and health.counters["skipped_frames"] == 2
    assert "2 skipped as non-TCP/UDP" in health.last_error


@pytest.mark.parametrize("content,message", [
    (b"", "empty file"),
    (b"\x00" * 10, "too short"),
    (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "bad magic"),
    (b"\x0a\x0d\x0d\x0a" + b"\x00" * 40, "pcapng is not supported"),
])
def test_invalid_files_fail_with_a_clear_reason_and_exit_4(tmp_path, capsys, content, message):
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(PcapError, match=message):
        replay(path)
    code, out, err = cli(capsys, "--pcap", str(path), "--dry-run")
    body = json.loads(out.strip().splitlines()[-1])
    assert code == 4 and body["status"] == "failed" and message in body["error"]
    assert json.loads(err.strip().splitlines()[-1])["status"] == "failed"


def test_a_failed_replay_sends_a_failed_heartbeat_with_the_reason(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not a pcap at all, just text....")
    beats, health = [], Health("pcap_replay", None, str(tmp_path / "h.json"))
    with pytest.raises(PcapError):
        run(PcapReplaySource(str(path)), FlowExtractor(), lambda _: None, health, heartbeat=beats.append)
    assert [b["status"] for b in beats] == ["starting", "failed"]
    assert beats[-1]["lastError"].startswith("pcap: not a pcap file")
    assert json.loads((tmp_path / "h.json").read_text())["status"] == "failed"


def test_unsupported_link_type_is_refused(tmp_path, capsys):
    path = write(tmp_path, [(T0, b"\x00" * 60)], linktype=105)  # IEEE 802.11
    with pytest.raises(PcapError, match="unsupported link type 105"):
        replay(path)
    code, out, _ = cli(capsys, "--pcap", str(path), "--dry-run")
    assert code == 4 and "unsupported link type 105" in out
    with pytest.raises(PcapError, match="unsupported link type"):
        parse_frame(b"\x00" * 60, 105, 0.0)


def test_corrupt_record_length_is_refused(tmp_path):
    path = write(tmp_path, tcp_session())
    data = bytearray(path.read_bytes())
    struct.pack_into("<I", data, 24 + 8, MAX_SNAPLEN + 1)  # first record's captured length
    path.write_bytes(bytes(data))
    with pytest.raises(PcapError, match="corrupt"):
        replay(path)


@pytest.mark.parametrize("cut", [5, 30])  # inside the last record's data / inside the last record's header
def test_truncated_pcap_replays_complete_records_and_reports_the_cut(tmp_path, capsys, cut):
    frames = tcp_session() + udp_exchange()
    path = write(tmp_path, frames)
    last_len = len(frames[-1][1])
    trim = cut if cut < last_len else last_len + 16 - 6  # 30: drop the data and all but 6 bytes of the header
    path.write_bytes(path.read_bytes()[:-trim])
    posted, health, beats = replay(path)
    assert beats[-1]["status"] == "finished"
    assert "pcap truncated" in health.last_error and health.counters["records"] == len(frames) - 1
    assert len(posted) == 2  # the TCP session and the one-packet UDP flow before the cut
    udp = next(p for p in posted if p["destinationIP"] == C)
    assert udp["total_fwd_packets"] == 1 and udp["total_bwd_packets"] == 0
    code, _, err = cli(capsys, "--pcap", str(path), "--dry-run")
    assert code == 0 and "pcap truncated" in json.loads(err.strip().splitlines()[-1])["lastError"]


def test_missing_file_and_directory_and_bad_limit(tmp_path, capsys):
    with pytest.raises(PcapError, match="not found"):
        PcapReplaySource(str(tmp_path / "nope.pcap"))
    with pytest.raises(PcapError, match="not a regular file"):
        PcapReplaySource(str(tmp_path))
    with pytest.raises(PcapError, match="at least 1"):
        PcapReplaySource(str(write(tmp_path, tcp_session())), max_packets=0)
    code, out, _ = cli(capsys, "--pcap", str(tmp_path / "nope.pcap"), "--dry-run")
    assert code == 4 and json.loads(out)["status"] == "failed"


def test_files_are_closed_after_success_and_failure(tmp_path):
    good, bad = write(tmp_path, tcp_session(), "good.pcap"), tmp_path / "bad.pcap"
    bad.write_bytes(b"\x00" * 30)
    replay(good)
    with pytest.raises(PcapError):
        replay(bad)
    os.remove(good)  # on Windows this fails if a handle were still open
    os.remove(bad)
    assert not good.exists() and not bad.exists()


# ── repeated replay and duplicates ─────────────────────────────────────────────────────────────────────────────────
def test_repeated_replay_is_deterministic(tmp_path):
    path = write(tmp_path, mixed_frames())
    first, _, _ = replay(path)
    second, _, _ = replay(path)
    assert first == second  # identical records: the backend stores each replay as new observations (documented)
    src = PcapReplaySource(str(path))
    a, b = list(src.packets()), list(src.packets())  # the same source object can be replayed again
    assert a == b and src.stats["records"] == 11


def test_duplicate_packets_inside_one_replay_stay_in_one_flow(tmp_path):
    frames = tcp_session()
    frames = frames[:4] + [frames[3]] + frames[4:]  # a retransmitted data segment
    posted, _, _ = replay(write(tmp_path, frames))
    assert len(posted) == 1 and posted[0]["total_fwd_packets"] == 5 and posted[0]["total_len_fwd_packets"] == 200


def test_rst_ends_a_flow_and_reused_ports_start_a_new_one(tmp_path):
    frames = [(T0, build_tcp_frame(A, B, 40001, 80, SYN)), (T0 + 0.01, build_tcp_frame(B, A, 80, 40001, RST | ACK)),
              (T0 + 0.02, build_tcp_frame(A, B, 40001, 80, SYN)), (T0 + 0.03, build_tcp_frame(B, A, 80, 40001, RST | ACK))]
    posted, _, _ = replay(write(tmp_path, frames))
    assert len(posted) == 2 and all(p["rst_flag_count"] == 1 for p in posted)


# ── no payload storage ─────────────────────────────────────────────────────────────────────────────────────────────
def test_payload_bytes_never_leave_the_parser(tmp_path, capsys):
    frames = [(T0, build_tcp_frame(A, B, 40000, 22, SYN)),
              (T0 + 0.01, tcp_frame_with_payload(A, B, 40000, 22, PSH | ACK, MARKER * 4)),
              (T0 + 0.02, tcp_frame_with_payload(B, A, 22, 40000, PSH | ACK, MARKER)),
              (T0 + 0.03, build_tcp_frame(A, B, 40000, 22, RST))]
    path = write(tmp_path, frames)
    health_file = tmp_path / "health.json"
    code, out, err = cli(capsys, "--pcap", str(path), "--dry-run", "--health-file", str(health_file))
    assert code == 0
    body = json.loads(out.strip())
    assert body["total_len_fwd_packets"] == len(MARKER) * 4 and body["total_len_bwd_packets"] == len(MARKER)
    for text in (out, err, health_file.read_text()):
        assert MARKER.decode() not in text
    assert not any(k in body for k in ("payload", "data", "raw", "bytes"))
    meta = parse_frame(frames[1][1], 1, T0)
    assert all(not isinstance(getattr(meta, f), (bytes, bytearray)) for f in meta.__dataclass_fields__)


# ── AI-engine integration ──────────────────────────────────────────────────────────────────────────────────────────
def _as_backend_sends(payload):
    """The backend forwards the flow fields; captureSource is kept by the backend, not sent to the engine."""
    return {k: v for k, v in payload.items() if k != "captureSource"}


class _StubPredictor:
    """Deterministic stand-in: records what the engine handed to the model."""
    def __init__(self):
        self.seen = []

    def predict(self, payload, explain=False):
        vec = [float(v) for v in extract_features_from_record(payload)]
        self.seen.append(vec)
        return {"predictedClass": "BENIGN", "threatScore": 0.05, "severity": "LOW", "action": "ALLOW",
                "isAnomaly": False, "anomalyScore": 0.0, "classProbabilities": {"BENIGN": 0.95},
                "modelVersion": "stub", "featureVector": vec, "featureSchemaVersion": "v2.1_53feat"}


@pytest.fixture
def engine_client():
    from fastapi.testclient import TestClient
    from inference import main as engine
    with patch("inference.main._notify"):
        with TestClient(engine.app) as c:
            yield c, engine


def test_replayed_flows_satisfy_the_engine_internal_contract(tmp_path, engine_client, monkeypatch):
    client, engine = engine_client
    stub = _StubPredictor()
    monkeypatch.setattr(engine, "predictor", stub)
    posted, _, _ = replay(write(tmp_path, mixed_frames()))
    for p in posted:
        r = client.post("/predict/internal", json=_as_backend_sends(p),
                        headers={"X-API-Key": os.environ["SENTINEL_KEY"]})
        assert r.status_code == 200, r.text
        res = r.json()["result"]
        assert res["defaultedFeatures"] == [] and res["incompleteInput"] is False
        assert len(res["featureVector"]) == 53
    assert len(stub.seen) == len(posted) == 2
    assert stub.seen[0] == [float(v) for v in extract_features_from_record(posted[0])]


def test_replayed_flows_score_with_the_deployed_model_read_only(tmp_path, engine_client):
    client, engine = engine_client
    if not engine.predictor or not getattr(engine.predictor, "_loaded", False):
        pytest.skip("deployed model not loadable here")
    posted, _, _ = replay(write(tmp_path, mixed_frames()))
    for p in posted:
        r = client.post("/predict/eval", json=_as_backend_sends(p), headers={"X-API-Key": os.environ["SENTINEL_KEY"]})
        assert r.status_code == 200, r.text
        res = r.json()["result"]
        assert 0.0 <= res["threatScore"] <= 1.0 and res["predictedClass"]
        assert res["defaultedFeatures"] == [] and res["incompleteInput"] is False
        assert "xgb_cicids_v1" in str(res.get("modelVersion", ""))
