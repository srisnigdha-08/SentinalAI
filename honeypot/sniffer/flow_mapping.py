"""
Map a cicflowmeter (Python package) CSV row to the backend's live-detection payload
(POST /api/honeypot/ingest/flow). Pure functions, no Scapy dependency, so they can be unit tested.

Column names follow the Python cicflowmeter output (snake_case, e.g. ``tot_fwd_pkts``). Units are passed
through unchanged; check them against the training data (CICFlowMeter Java: durations/IATs in
microseconds) before relying on live scores — see honeypot/README.md.
"""
import math
from datetime import datetime, timezone

# cicflowmeter column -> SentinelAI Record field
CICFLOWMETER_TO_RECORD = {
    "flow_duration": "flow_duration",
    "tot_fwd_pkts": "total_fwd_packets",
    "tot_bwd_pkts": "total_bwd_packets",
    "totlen_fwd_pkts": "total_len_fwd_packets",
    "totlen_bwd_pkts": "total_len_bwd_packets",
    "fwd_pkt_len_max": "fwd_packet_len_max",
    "fwd_pkt_len_min": "fwd_packet_len_min",
    "fwd_pkt_len_mean": "fwd_packet_len_mean",
    "fwd_pkt_len_std": "fwd_packet_len_std",
    "bwd_pkt_len_max": "bwd_packet_len_max",
    "bwd_pkt_len_min": "bwd_packet_len_min",
    "bwd_pkt_len_mean": "bwd_packet_len_mean",
    "bwd_pkt_len_std": "bwd_packet_len_std",
    "flow_byts_s": "flow_bytes_per_sec",
    "flow_pkts_s": "flow_packets_per_sec",
    "flow_iat_mean": "flow_iat_mean",
    "flow_iat_std": "flow_iat_std",
    "flow_iat_max": "flow_iat_max",
    "flow_iat_min": "flow_iat_min",
    "fwd_iat_tot": "fwd_iat_total",
    "fwd_iat_mean": "fwd_iat_mean",
    "fwd_iat_std": "fwd_iat_std",
    "fwd_iat_max": "fwd_iat_max",
    "fwd_iat_min": "fwd_iat_min",
    "bwd_iat_tot": "bwd_iat_total",
    "bwd_iat_mean": "bwd_iat_mean",
    "bwd_iat_std": "bwd_iat_std",
    "bwd_iat_max": "bwd_iat_max",
    "bwd_iat_min": "bwd_iat_min",
    "fwd_psh_flags": "fwd_psh_flags",
    "bwd_psh_flags": "bwd_psh_flags",
    "fwd_urg_flags": "fwd_urg_flags",
    "bwd_urg_flags": "bwd_urg_flags",
    "fin_flag_cnt": "fin_flag_count",
    "syn_flag_cnt": "syn_flag_count",
    "rst_flag_cnt": "rst_flag_count",
    "psh_flag_cnt": "psh_flag_count",
    "ack_flag_cnt": "ack_flag_count",
    "urg_flag_cnt": "urg_flag_count",
    "fwd_header_len": "fwd_header_len",
    "bwd_header_len": "bwd_header_len",
    "fwd_byts_b_avg": "fwd_avg_bytes_per_bulk",
    "bwd_byts_b_avg": "bwd_avg_bytes_per_bulk",
    "init_fwd_win_byts": "init_win_bytes_forward",
    "init_bwd_win_byts": "init_win_bytes_backward",
    "active_mean": "active_mean",
    "active_std": "active_std",
    "idle_mean": "idle_mean",
    "idle_std": "idle_std",
    "down_up_ratio": "down_up_ratio",
}


def _number(value):
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n if math.isfinite(n) else None


def to_detection_payload(row: dict):
    """CSV row -> payload dict, or None when the row has no source IP."""
    src = (row.get("src_ip") or "").strip()
    if not src:
        return None
    payload = {"sourceIP": src}
    dst = (row.get("dst_ip") or "").strip()
    if dst:
        payload["destinationIP"] = dst
    ts = (row.get("timestamp") or "").strip()
    if ts:
        try:
            payload["timestamp"] = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    for column, field in CICFLOWMETER_TO_RECORD.items():
        n = _number(row.get(column))
        if n is not None:
            payload[field] = n
    return payload
