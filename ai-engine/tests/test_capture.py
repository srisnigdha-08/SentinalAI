"""Passive capture adapter (ai-engine/capture): parsing, flow features, parity with the 53-feature contract, guards."""
import dataclasses
import io
import json
import math

import pytest

from capture.flows import EMITTED_FEATURES, ENGINE_DERIVED, FlowExtractor, to_ingest_payload
from capture.packets import (ACK, FIN, PSH, SYN, PacketMeta, PcapError, build_tcp_frame, build_udp_frame, parse_frame,
                             read_pcap, write_pcap)
from capture.service import Health, run
from capture.sources import CaptureUnavailable, PcapReplaySource, check_live_capture
from utils.features import FEATURE_NAMES, compute_payload_entropy, extract_features_from_record

A, B = "192.0.2.10", "198.51.100.20"


def handshake_flow(t0=1_700_000_000.0):
    """client A:40000 -> server B:22: SYN, SYN/ACK, ACK, 100 B data, 300 B reply, FIN both ways."""
    return [
        (t0 + 0.000, build_tcp_frame(A, B, 40000, 22, SYN, window=64240)),
        (t0 + 0.001, build_tcp_frame(B, A, 22, 40000, SYN | ACK, window=65160)),
        (t0 + 0.002, build_tcp_frame(A, B, 40000, 22, ACK)),
        (t0 + 0.010, build_tcp_frame(A, B, 40000, 22, PSH | ACK, payload_len=100)),
        (t0 + 0.020, build_tcp_frame(B, A, 22, 40000, PSH | ACK, payload_len=300)),
        (t0 + 0.030, build_tcp_frame(A, B, 40000, 22, FIN | ACK)),
        (t0 + 0.031, build_tcp_frame(B, A, 22, 40000, FIN | ACK)),
    ]


def pcap_of(tmp_path, frames, name="t.pcap"):
    p = tmp_path / name
    write_pcap(p, frames)
    return p


def test_packet_meta_has_no_payload_field():
    names = {f.name for f in dataclasses.fields(PacketMeta)}
    assert names == {"ts", "src", "dst", "sport", "dport", "proto", "payload_len", "header_len", "flags", "window"}


def test_parse_tcp_and_udp_headers():
    m = parse_frame(build_tcp_frame(A, B, 1, 2, SYN, window=1234, payload_len=7, options_len=12), 1, 5.0)
    assert (m.src, m.dst, m.sport, m.dport, m.proto) == (A, B, 1, 2, 6)
    assert (m.payload_len, m.header_len, m.flags, m.window) == (7, 32, SYN, 1234)
    u = parse_frame(build_udp_frame(A, B, 53, 5353, payload_len=40), 1, 5.0)
    assert (u.proto, u.payload_len, u.header_len, u.window) == (17, 40, 8, -1)


def test_non_ip_frames_are_ignored():
    arp = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28
    assert parse_frame(arp, 1, 0.0) is None


def test_handshake_flow_features_match_cicflowmeter_definitions(tmp_path):
    recs = list(FlowExtractor().run(PcapReplaySource(str(pcap_of(tmp_path, handshake_flow()))).packets()))
    assert len(recs) == 1
    r = recs[0]
    f = r["features"]
    assert (r["sourceIP"], r["destinationIP"], r["destinationPort"]) == (A, B, 22)
    assert f["flow_duration"] == pytest.approx(31_000, abs=1)          # microseconds
    assert (f["total_fwd_packets"], f["total_bwd_packets"]) == (4, 3)
    assert (f["total_len_fwd_packets"], f["total_len_bwd_packets"]) == (100, 300)  # payload bytes
    assert f["fwd_packet_len_max"] == 100 and f["fwd_packet_len_min"] == 0
    assert f["bwd_packet_len_mean"] == pytest.approx(100.0)
    assert f["init_win_bytes_forward"] == 64240 and f["init_win_bytes_backward"] == 65160
    assert (f["syn_flag_count"], f["fin_flag_count"], f["psh_flag_count"]) == (2, 2, 2)
    assert f["ack_flag_count"] == 6 and f["fwd_psh_flags"] == 1 and f["bwd_psh_flags"] == 1
    assert f["fwd_header_len"] == 80 and f["bwd_header_len"] == 60
    assert f["flow_iat_max"] == pytest.approx(10_000, abs=1) and f["flow_iat_min"] == pytest.approx(1_000, abs=1)
    assert f["fwd_iat_total"] == pytest.approx(30_000, abs=1)
    assert f["flow_bytes_per_sec"] == pytest.approx(400 / 0.031, rel=1e-3)
    assert f["down_up_ratio"] == 0.0                                     # floor(3 / 4), CICFlowMeter integer ratio
    assert f["fwd_avg_bytes_per_bulk"] == 0.0 and f["bwd_avg_bytes_per_bulk"] == 0.0


def test_active_idle_split_on_5s_gap(tmp_path):
    t0 = 1_700_000_000.0
    frames = [(t0, build_udp_frame(A, B, 5000, 53, 10)), (t0 + 1, build_udp_frame(B, A, 53, 5000, 10)),
              (t0 + 10, build_udp_frame(A, B, 5000, 53, 10)), (t0 + 11, build_udp_frame(B, A, 53, 5000, 10))]
    (r,) = list(FlowExtractor().run(PcapReplaySource(str(pcap_of(tmp_path, frames))).packets()))
    assert r["features"]["idle_mean"] == pytest.approx(9e6, rel=1e-6)
    assert r["features"]["active_mean"] == pytest.approx(1e6, rel=1e-6)
    assert r["features"]["init_win_bytes_forward"] == -1                 # UDP: no TCP window


def test_idle_timeout_splits_flows(tmp_path):
    t0 = 1_700_000_000.0
    frames = [(t0, build_udp_frame(A, B, 5000, 53, 10)), (t0 + 200, build_udp_frame(A, B, 5000, 53, 10))]
    recs = list(FlowExtractor().run(PcapReplaySource(str(pcap_of(tmp_path, frames))).packets()))
    assert len(recs) == 2


def test_resource_limits_evict_and_split():
    ex = FlowExtractor(max_flows=2, max_packets_per_flow=3)
    out = []
    for i in range(3):  # three concurrent flows with room for two: the oldest is exported early
        out += list(ex.add(PacketMeta(10.0 + i, A, B, 1000 + i, 80, 17, 1, 8, 0, -1)))
    assert ex.stats["evicted_capacity"] == 1 and len(out) == 1
    for j in range(3):
        out += list(ex.add(PacketMeta(20.0 + j, A, B, 9999, 80, 17, 1, 8, 0, -1)))
    assert ex.stats["split_packet_limit"] == 1


def test_pcapng_and_garbage_are_refused():
    with pytest.raises(PcapError, match="pcapng"):
        list(read_pcap(io.BytesIO(b"\x0a\x0d\x0d\x0a" + b"\x00" * 28)))
    with pytest.raises(PcapError, match="magic"):
        list(read_pcap(io.BytesIO(b"\x00" * 24)))
    with pytest.raises(PcapError, match="too short"):
        list(read_pcap(io.BytesIO(b"\x00")))


def test_emitted_plus_engine_derived_is_exactly_the_53_feature_schema():
    assert sorted(EMITTED_FEATURES + ENGINE_DERIVED) == sorted(FEATURE_NAMES)
    assert len(EMITTED_FEATURES) == 50


def test_parity_record_to_engine_vector(tmp_path):
    """The record the capture posts becomes the engine's 53-vector with no defaulted field."""
    (r,) = list(FlowExtractor().run(PcapReplaySource(str(pcap_of(tmp_path, handshake_flow()))).packets()))
    payload = to_ingest_payload(r, "pcap_replay")
    vec = extract_features_from_record(payload)
    assert len(vec) == 53
    for i, name in enumerate(FEATURE_NAMES):
        if name in EMITTED_FEATURES:
            assert vec[i] == pytest.approx(r["features"][name]), name
    assert vec[FEATURE_NAMES.index("payload_entropy")] == pytest.approx(compute_payload_entropy(100, 300))


def test_ingest_payload_carries_an_honest_source_label(tmp_path):
    (r,) = list(FlowExtractor().run(PcapReplaySource(str(pcap_of(tmp_path, handshake_flow()))).packets()))
    assert to_ingest_payload(r, "pcap_replay")["captureSource"] == "pcap_replay"
    with pytest.raises(ValueError):
        to_ingest_payload(r, "live")  # anything but the two defined labels is refused


@pytest.mark.parametrize("env,confirm,iface,ifaces,reason", [
    ({}, True, "eth0", ["eth0"], "disabled"),
    ({"SENTINEL_LIVE_CAPTURE": "1"}, False, "eth0", ["eth0"], "confirmation"),
    ({"SENTINEL_LIVE_CAPTURE": "1"}, True, "any", ["any"], "exactly one"),
    ({"SENTINEL_LIVE_CAPTURE": "1"}, True, "eth*", ["eth0"], "exactly one"),
    ({"SENTINEL_LIVE_CAPTURE": "1", "SENTINEL_CAPTURE_INTERFACES": "eth1"}, True, "eth0", ["eth0", "eth1"], "not in"),
    ({"SENTINEL_LIVE_CAPTURE": "1"}, True, "eth9", ["eth0"], "not found"),
])
def test_live_capture_guards(env, confirm, iface, ifaces, reason):
    with pytest.raises(CaptureUnavailable, match=reason):
        check_live_capture(iface, confirm, env=env, interfaces=ifaces)


def test_live_capture_guard_passes_only_with_everything_set():
    check_live_capture("eth0", True, env={"SENTINEL_LIVE_CAPTURE": "1", "SENTINEL_CAPTURE_INTERFACES": "eth0"},
                       interfaces=["eth0", "lo"])


def test_service_run_reports_health_and_rate_limits(tmp_path):
    frames = []
    for i in range(30):
        frames += [(1_700_000_000.0 + i * 0.001, build_udp_frame(A, B, 20000 + i, 53, 12))]
    src = PcapReplaySource(str(pcap_of(tmp_path, frames)))
    posted, beats = [], []
    health = Health("pcap_replay", None, str(tmp_path / "health.json"))
    run(src, FlowExtractor(), posted.append, health, heartbeat=beats.append, heartbeat_seconds=0.0,
        max_flows_per_second=10)
    assert health.counters["flows"] == 30
    assert health.counters["posted"] == 10 and health.counters["rate_limited"] == 20
    assert all(p["captureSource"] == "pcap_replay" for p in posted)
    snap = json.loads((tmp_path / "health.json").read_text())
    assert snap["status"] == "finished" and snap["mode"] == "pcap_replay"
    assert beats and beats[-1]["status"] == "finished"


def test_service_survives_a_failing_sink(tmp_path):
    src = PcapReplaySource(str(pcap_of(tmp_path, handshake_flow())))
    health = Health("pcap_replay", None)

    def boom(_):
        raise ConnectionError("backend down")
    run(src, FlowExtractor(), boom, health)
    assert health.counters["post_errors"] == 1 and "ConnectionError" in health.last_error


def test_cli_dry_run_prints_labelled_flows(tmp_path, capsys):
    from capture.service import main
    assert main(["--pcap", str(pcap_of(tmp_path, handshake_flow())), "--dry-run"]) == 0
    line = capsys.readouterr().out.strip().splitlines()[0]
    body = json.loads(line)
    assert body["captureSource"] == "pcap_replay" and body["sourceIP"] == A
    assert not any(k in body for k in ("payload", "data", "raw"))
    assert math.isclose(body["flow_duration"], 31000, abs_tol=1)


def test_cli_live_without_opt_in_reports_unavailable(capsys, monkeypatch):
    from capture.service import main
    monkeypatch.delenv("SENTINEL_LIVE_CAPTURE", raising=False)
    assert main(["--live", "--iface", "eth0"]) == 3
    assert json.loads(capsys.readouterr().out)["mode"] == "unavailable"
