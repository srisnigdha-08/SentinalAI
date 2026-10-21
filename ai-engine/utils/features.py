"""
SentinelAI Feature Extraction Pipeline
53-feature vector aligned with CICIDS2017 + Advanced Engineered Features
"""
import numpy as np
import pandas as pd
import datetime
import logging

_features_log = logging.getLogger("sentinel.features")

FEATURE_NAMES = [
    "flow_duration","total_fwd_packets","total_bwd_packets",
    "total_len_fwd_packets","total_len_bwd_packets",
    "fwd_packet_len_max","fwd_packet_len_min","fwd_packet_len_mean","fwd_packet_len_std",
    "bwd_packet_len_max","bwd_packet_len_min","bwd_packet_len_mean","bwd_packet_len_std",
    "flow_bytes_per_sec","flow_packets_per_sec",
    "flow_iat_mean","flow_iat_std","flow_iat_max","flow_iat_min",
    "fwd_iat_total","fwd_iat_mean","fwd_iat_std","fwd_iat_max","fwd_iat_min",
    "bwd_iat_total","bwd_iat_mean","bwd_iat_std","bwd_iat_max","bwd_iat_min",
    "fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
    "fin_flag_count","syn_flag_count","rst_flag_count","psh_flag_count",
    "ack_flag_count","urg_flag_count",
    "fwd_header_len","bwd_header_len",
    "fwd_avg_bytes_per_bulk","bwd_avg_bytes_per_bulk",
    "init_win_bytes_forward","init_win_bytes_backward",
    "active_mean","active_std","idle_mean","idle_std",
    "down_up_ratio",
    "payload_entropy", "time_of_day_sin", "time_of_day_cos",
]

# Guard against silent feature drift across code, models, and docstrings
EXPECTED_FEATURE_COUNT = 53
FEATURE_SCHEMA_VERSION = "v2.1_53feat"
assert len(FEATURE_NAMES) == EXPECTED_FEATURE_COUNT, (
    f"FEATURE_NAMES drift detected: expected {EXPECTED_FEATURE_COUNT} features, got {len(FEATURE_NAMES)}. "
    "If FEATURE_NAMES was modified, update EXPECTED_FEATURE_COUNT, the module docstring, and re-train models."
)

LABEL_MAP = {
    "BENIGN":0,"SSH Brute Force":1,"SQL Injection":2,"Port Scan":3,
    "DDoS":4,"RCE Attempt":5,"XSS Attempt":6,"Malware Beacon":7,
    "Credential Stuffing":8,"Lateral Movement":9,"Data Exfiltration":10,
}
LABEL_NAMES = {v:k for k,v in LABEL_MAP.items()}

RAW_LABEL_TO_TARGET = {
    "BENIGN": "BENIGN",
    "SSH-Patator": "SSH Brute Force",
    "FTP-Patator": "Credential Stuffing",
    "PortScan": "Port Scan",
    "DDoS": "DDoS",
    "Bot": "Malware Beacon",
    "DoS Hulk": "DDoS",
    "DoS GoldenEye": "DDoS",
    "DoS slowloris": "DDoS",
    "DoS Slowhttptest": "DDoS",
    "Heartbleed": "RCE Attempt",
    "Infiltration": "Lateral Movement",
    "Web Attack \ufffd Brute Force": "Credential Stuffing",
    "Web Attack \ufffd XSS": "XSS Attempt",
    "Web Attack \ufffd Sql Injection": "SQL Injection"
}

CANDIDATES = {
    "flow_duration": ["flow_duration", "Flow Duration"],
    "total_fwd_packets": ["total_fwd_packets", "Total Fwd Packets", "tot_fwd_pkts"],
    "total_bwd_packets": ["total_bwd_packets", "total_backward_packets", "Total Backward Packets", "tot_bwd_pkts"],
    "total_len_fwd_packets": ["total_len_fwd_packets", "total_length_of_fwd_packets", "Total Length of Fwd Packets", "totlen_fwd_pkts"],
    "total_len_bwd_packets": ["total_len_bwd_packets", "total_length_of_bwd_packets", "Total Length of Bwd Packets", "totlen_bwd_pkts"],
    
    "fwd_packet_len_max": ["fwd_packet_len_max", "fwd_packet_length_max", "Fwd Packet Length Max", "fwd_pkt_len_max"],
    "fwd_packet_len_min": ["fwd_packet_len_min", "fwd_packet_length_min", "Fwd Packet Length Min", "fwd_pkt_len_min"],
    "fwd_packet_len_mean": ["fwd_packet_len_mean", "fwd_packet_length_mean", "Fwd Packet Length Mean", "fwd_pkt_len_mean"],
    "fwd_packet_len_std": ["fwd_packet_len_std", "fwd_packet_length_std", "Fwd Packet Length Std", "fwd_pkt_len_std"],
    
    "bwd_packet_len_max": ["bwd_packet_len_max", "bwd_packet_length_max", "Bwd Packet Length Max", "bwd_pkt_len_max"],
    "bwd_packet_len_min": ["bwd_packet_len_min", "bwd_packet_length_min", "Bwd Packet Length Min", "bwd_pkt_len_min"],
    "bwd_packet_len_mean": ["bwd_packet_len_mean", "bwd_packet_length_mean", "Bwd Packet Length Mean", "bwd_pkt_len_mean"],
    "bwd_packet_len_std": ["bwd_packet_len_std", "bwd_packet_length_std", "Bwd Packet Length Std", "bwd_pkt_len_std"],
    
    "flow_bytes_per_sec": ["flow_bytes_per_sec", "flow_bytes_per_s", "Flow Bytes/s", "flow_byts_s"],
    "flow_packets_per_sec": ["flow_packets_per_sec", "flow_packets_per_s", "Flow Packets/s", "flow_pkts_s"],
    
    "flow_iat_mean": ["flow_iat_mean", "Flow IAT Mean"],
    "flow_iat_std": ["flow_iat_std", "Flow IAT Std"],
    "flow_iat_max": ["flow_iat_max", "Flow IAT Max"],
    "flow_iat_min": ["flow_iat_min", "Flow IAT Min"],
    
    "fwd_iat_total": ["fwd_iat_total", "Fwd IAT Total", "fwd_iat_tot"],
    "fwd_iat_mean": ["fwd_iat_mean", "Fwd IAT Mean"],
    "fwd_iat_std": ["fwd_iat_std", "Fwd IAT Std"],
    "fwd_iat_max": ["fwd_iat_max", "Fwd IAT Max"],
    "fwd_iat_min": ["fwd_iat_min", "Fwd IAT Min"],
    
    "bwd_iat_total": ["bwd_iat_total", "Bwd IAT Total", "bwd_iat_tot"],
    "bwd_iat_mean": ["bwd_iat_mean", "Bwd IAT Mean"],
    "bwd_iat_std": ["bwd_iat_std", "Bwd IAT Std"],
    "bwd_iat_max": ["bwd_iat_max", "Bwd IAT Max"],
    "bwd_iat_min": ["bwd_iat_min", "Bwd IAT Min"],
    
    "fwd_psh_flags": ["fwd_psh_flags", "Fwd PSH Flags"],
    "bwd_psh_flags": ["bwd_psh_flags", "Bwd PSH Flags"],
    "fwd_urg_flags": ["fwd_urg_flags", "Fwd URG Flags"],
    "bwd_urg_flags": ["bwd_urg_flags", "Bwd URG Flags"],
    
    "fin_flag_count": ["fin_flag_count", "FIN Flag Count", "fin_flag_cnt"],
    "syn_flag_count": ["syn_flag_count", "SYN Flag Count", "syn_flag_cnt"],
    "rst_flag_count": ["rst_flag_count", "RST Flag Count", "rst_flag_cnt"],
    "psh_flag_count": ["psh_flag_count", "PSH Flag Count", "psh_flag_cnt"],
    "ack_flag_count": ["ack_flag_count", "ACK Flag Count", "ack_flag_cnt"],
    "urg_flag_count": ["urg_flag_count", "URG Flag Count", "urg_flag_cnt"],
    
    "fwd_header_len": ["fwd_header_len", "fwd_header_length", "Fwd Header Length"],
    "bwd_header_len": ["bwd_header_len", "bwd_header_length", "Bwd Header Length"],
    
    "fwd_avg_bytes_per_bulk": ["fwd_avg_bytes_per_bulk", "Fwd Avg Bytes/Bulk", "fwd_byts_b_avg"],
    "bwd_avg_bytes_per_bulk": ["bwd_avg_bytes_per_bulk", "Bwd Avg Bytes/Bulk", "bwd_byts_b_avg"],
    
    "init_win_bytes_forward": ["init_win_bytes_forward", "Init_Win_bytes_forward", "Init Win bytes forward", "init_win_bytes_fwd", "init_fwd_win_byts"],
    "init_win_bytes_backward": ["init_win_bytes_backward", "Init_Win_bytes_backward", "Init Win bytes backward", "init_win_bytes_bwd", "init_bwd_win_byts"],
    "active_mean": ["active_mean", "Active Mean", "active mean"],
    "active_std": ["active_std", "Active Std", "active std"],
    "idle_mean": ["idle_mean", "Idle Mean", "idle mean"],
    "idle_std": ["idle_std", "Idle Std", "idle std"],
    "down_up_ratio": ["down_up_ratio", "Down/Up Ratio", "down up ratio"],
    
    "payload_entropy": ["payload_entropy"],
    "time_of_day_sin": ["time_of_day_sin"],
    "time_of_day_cos": ["time_of_day_cos"],
}

def compute_payload_entropy(fwd_len: float, bwd_len: float) -> float:
    total = float(fwd_len) + float(bwd_len)
    if total <= 0.0:
        return 0.0
    p_f = float(fwd_len) / total
    p_b = float(bwd_len) / total
    entropy = 0.0
    if p_f > 0.0:
        entropy -= p_f * np.log2(p_f)
    if p_b > 0.0:
        entropy -= p_b * np.log2(p_b)
    return float(entropy)

def compute_time_of_day(timestamp_val) -> tuple:
    """
    Computes cyclical time-of-day coordinates (sin, cos) under a consistent UTC policy.

    Feature Contract & Policy:
    - Target: Normalized 24-hour cyclical coordinates on the unit circle:
        theta = 2 * pi * (hour + min/60 + sec/3600 + microsec/3600e6) / 24.0
        return (float(sin(theta)), float(cos(theta)))
    - Deterministic Fallback: If timestamp_val is None, empty, non-finite, or cannot
      be parsed, returns (0.0, 0.0). This deterministic neutral origin eliminates
      inference dependency on host server wall-clock time (datetime.now()) and aligns
      with the training-time convention in prepare_features() where missing time
      features were filled with 0.0.
    - Consistent UTC Policy:
      * Unix epoch numbers (int/float seconds) are parsed as UTC via datetime.fromtimestamp(ts, tz=datetime.timezone.utc).
      * Timezone-aware datetimes/strings are converted to UTC via astimezone(datetime.timezone.utc).
      * Timezone-naive datetimes/strings are explicitly interpreted as UTC.
      * Non-finite floats (NaN, Inf) and out-of-range timestamps return (0.0, 0.0).
    """
    if timestamp_val is None:
        return 0.0, 0.0

    dt = None

    if isinstance(timestamp_val, (int, float)):
        try:
            val = float(timestamp_val)
            if not np.isfinite(val):
                return 0.0, 0.0
            # Guard against extreme timestamps that raise OverflowError / OSError
            # Allow valid range from year 1 to 9999 (-62135596800.0 to 253402300799.0)
            if not (-62135596800.0 <= val <= 253402300799.0):
                return 0.0, 0.0
            dt = datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc)
        except (ValueError, OverflowError, OSError):
            return 0.0, 0.0

    elif isinstance(timestamp_val, datetime.datetime):
        if timestamp_val.tzinfo is None:
            # Naive datetime: explicitly interpret as UTC
            dt = timestamp_val.replace(tzinfo=datetime.timezone.utc)
        else:
            # Aware datetime: explicitly convert to UTC
            dt = timestamp_val.astimezone(datetime.timezone.utc)

    elif isinstance(timestamp_val, str):
        ts_str = timestamp_val.strip()
        if not ts_str or ts_str.lower() in ("none", "null", "nan"):
            return 0.0, 0.0

        # 1. Attempt parsing as numeric Unix epoch string (e.g. "1500000000")
        try:
            val = float(ts_str)
            if np.isfinite(val) and (-62135596800.0 <= val <= 253402300799.0):
                dt = datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc)
        except (ValueError, OverflowError, OSError):
            dt = None

        # 2. If not numeric epoch, attempt ISO-8601 parsing
        if dt is None:
            try:
                # Replace trailing 'Z' with '+00:00' for broad ISO-8601 compatibility
                iso_candidate = ts_str[:-1] + "+00:00" if ts_str.endswith("Z") else ts_str
                parsed_dt = datetime.datetime.fromisoformat(iso_candidate)
                if parsed_dt.tzinfo is None:
                    dt = parsed_dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    dt = parsed_dt.astimezone(datetime.timezone.utc)
            except (ValueError, TypeError):
                dt = None

        # 3. If ISO fails, attempt standard tabular / CSV date-time formats
        if dt is None:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                try:
                    parsed_dt = datetime.datetime.strptime(ts_str, fmt)
                    dt = parsed_dt.replace(tzinfo=datetime.timezone.utc)
                    break
                except (ValueError, TypeError):
                    continue

        if dt is None:
            return 0.0, 0.0

    else:
        # Unsupported type (e.g., list, dict, object)
        return 0.0, 0.0

    # Extract time components in UTC
    hour_val = dt.hour + dt.minute / 60.0 + dt.second / 3600.0 + dt.microsecond / 3600000000.0
    sin_val = np.sin(2.0 * np.pi * hour_val / 24.0)
    cos_val = np.cos(2.0 * np.pi * hour_val / 24.0)
    return float(sin_val), float(cos_val)

def extract_features_from_record(record: dict) -> np.ndarray:
    # Build normalized lookup for keys with leading/trailing whitespace or alternate casing
    norm_lookup = None

    def g(k, d=0.0):
        # 1. Direct match on key
        if k in record and record[k] is not None:
            try:
                v = float(record[k])
                if not (np.isnan(v) or np.isinf(v)):
                    return v
            except (ValueError, TypeError):
                pass

        # 2. Candidate names match
        cands = CANDIDATES.get(k, [])
        for c in cands:
            if c in record and record[c] is not None:
                try:
                    v = float(record[c])
                    if not (np.isnan(v) or np.isinf(v)):
                        return v
                except (ValueError, TypeError):
                    pass

        # 3. Normalized fallback (strip whitespace and lowercase)
        nonlocal norm_lookup
        if norm_lookup is None:
            norm_lookup = {}
            for rk, rv in record.items():
                if rv is not None:
                    clean_k = str(rk).strip().lower().replace("_", "").replace(" ", "").replace("/", "")
                    norm_lookup[clean_k] = rv
                    norm_lookup[str(rk).strip()] = rv

        for c in [k] + cands:
            if c in norm_lookup:
                try:
                    v = float(norm_lookup[c])
                    if not (np.isnan(v) or np.isinf(v)):
                        return v
                except (ValueError, TypeError):
                    pass
            c_norm = c.lower().replace("_", "").replace(" ", "").replace("/", "")
            if c_norm in norm_lookup:
                try:
                    v = float(norm_lookup[c_norm])
                    if not (np.isnan(v) or np.isinf(v)):
                        return v
                except (ValueError, TypeError):
                    pass

        return float(d)

    fwd_len = g("total_len_fwd_packets", 60.0)
    bwd_len = g("total_len_bwd_packets", 0.0)

    entropy = compute_payload_entropy(fwd_len, bwd_len)
    ts_val = record.get("timestamp") or record.get("Timestamp")
    t_sin, t_cos = compute_time_of_day(ts_val)

    return np.array([
        g("flow_duration",1000.0),g("total_fwd_packets",1.0),g("total_bwd_packets",0.0),
        fwd_len, bwd_len,
        g("fwd_packet_len_max",60.0),g("fwd_packet_len_min",60.0),g("fwd_packet_len_mean",60.0),g("fwd_packet_len_std",0.0),
        g("bwd_packet_len_max",0.0),g("bwd_packet_len_min",0.0),g("bwd_packet_len_mean",0.0),g("bwd_packet_len_std",0.0),
        g("flow_bytes_per_sec",60000.0),g("flow_packets_per_sec",1000.0),
        g("flow_iat_mean",1000.0),g("flow_iat_std",0.0),g("flow_iat_max",1000.0),g("flow_iat_min",1000.0),
        g("fwd_iat_total",0.0),g("fwd_iat_mean",0.0),g("fwd_iat_std",0.0),g("fwd_iat_max",0.0),g("fwd_iat_min",0.0),
        g("bwd_iat_total",0.0),g("bwd_iat_mean",0.0),g("bwd_iat_std",0.0),g("bwd_iat_max",0.0),g("bwd_iat_min",0.0),
        g("fwd_psh_flags",0.0),g("bwd_psh_flags",0.0),g("fwd_urg_flags",0.0),g("bwd_urg_flags",0.0),
        g("fin_flag_count",0.0),g("syn_flag_count",1.0),g("rst_flag_count",0.0),g("psh_flag_count",0.0),
        g("ack_flag_count",0.0),g("urg_flag_count",0.0),
        g("fwd_header_len",20.0),g("bwd_header_len",0.0),
        g("fwd_avg_bytes_per_bulk",0.0),g("bwd_avg_bytes_per_bulk",0.0),
        g("init_win_bytes_forward",0.0),g("init_win_bytes_backward",0.0),
        g("active_mean",0.0),g("active_std",0.0),g("idle_mean",0.0),g("idle_std",0.0),
        g("down_up_ratio",0.0),
        entropy, t_sin, t_cos
    ], dtype=np.float64)

def classify_honeypot_session(session: dict) -> str:
    """
    Rule-based class of a Cowrie session (login outcome, command keywords, IOC count, duration).
    This is the honeypot verdict served by predictor.predict_from_honeypot: Cowrie records no packet
    statistics, so there is no flow for the CICIDS-trained classifier to score.
    """
    cmds = session.get("commands", [])
    cmd_str = " ".join(str(c.get("command", "")).lower() for c in cmds)
    login_ok = bool(session.get("loginSucceeded", False))
    dur_sec = float(session.get("durationSeconds", 1))
    ioc_cnt = int(session.get("iocCount", 0))

    if not login_ok:
        return "SSH Brute Force"
    if len(cmds) == 0:
        return "Port Scan"
    if ioc_cnt >= 3 or dur_sec > 120 or any(k in cmd_str for k in ["scp", "ftp", "sftp", "rsync", "tar", "zip", "nc", "netcat"]):
        return "Data Exfiltration"
    if any(k in cmd_str for k in ["ssh ", "telnet", "ping", "nmap", "arp", "route", "smb", "mount"]):
        return "Lateral Movement"
    if any(k in cmd_str for k in ["wget", "curl", "chmod", "./", "python", "perl", "bash", "sh", "gcc"]):
        return "RCE Attempt"
    return "BENIGN"


def extract_features_from_honeypot(session: dict) -> np.ndarray:
    """
    Representative 53-feature flow for a session's rule class. Not used for serving: the per-profile
    means match utils/data_generator.py (synthetic data), and the CICIDS-trained classifier scores every
    one of these vectors as BENIGN, so predict_from_honeypot returns the rule verdict instead.
    """
    profile_name = classify_honeypot_session(session)

    PROFILES_MEANS = {
        "BENIGN":             {"dur": 65000.0,  "bps": 6500.0,    "pps": 250.0,   "syn": 0.5},
        "SSH Brute Force":    {"dur": 650.0,    "bps": 200000.0,  "pps": 5000.0,  "syn": 2.0},
        "SQL Injection":      {"dur": 2000.0,   "bps": 15000.0,   "pps": 500.0,   "syn": 1.5},
        "Port Scan":          {"dur": 12.5,     "bps": 500000.0,  "pps": 80000.0, "syn": 1.5},
        "DDoS":               {"dur": 100000.0, "bps": 2000000.0, "pps": 50000.0, "syn": 1.5},
        "RCE Attempt":        {"dur": 4000.0,   "bps": 20000.0,   "pps": 600.0,   "syn": 1.5},
        "XSS Attempt":        {"dur": 1500.0,   "bps": 12000.0,   "pps": 400.0,   "syn": 1.5},
        "Malware Beacon":     {"dur": 200.0,    "bps": 1000.0,    "pps": 40.0,    "syn": 1.5},
        "Credential Stuffing":{"dur": 800.0,    "bps": 8000.0,    "pps": 300.0,   "syn": 1.5},
        "Lateral Movement":   {"dur": 150.0,    "bps": 3000.0,    "pps": 800.0,   "syn": 1.5},
        "Data Exfiltration":  {"dur": 300000.0, "bps": 1500000.0, "pps": 120.0,   "syn": 1.5},
    }
    
    p = PROFILES_MEANS[profile_name]
    dur = p["dur"]
    bps = p["bps"]
    pps = p["pps"]
    syn = p["syn"]
    fwd = 10
    bwd = 5
    fwd_len = fwd * 80
    bwd_len = bwd * 150
    
    timestamp = session.get("startTime") or session.get("timestamp")
    
    return extract_features_from_record({
        "flow_duration": dur,
        "total_fwd_packets": float(fwd),
        "total_bwd_packets": float(bwd),
        "total_len_fwd_packets": float(fwd_len),
        "total_len_bwd_packets": float(bwd_len),
        "fwd_packet_len_max": 100.0,
        "fwd_packet_len_min": 40.0,
        "fwd_packet_len_mean": 80.0,
        "fwd_packet_len_std": 10.0,
        "bwd_packet_len_max": 200.0,
        "bwd_packet_len_min": 80.0,
        "bwd_packet_len_mean": 150.0,
        "bwd_packet_len_std": 15.0,
        "flow_bytes_per_sec": bps,
        "flow_packets_per_sec": pps,
        "flow_iat_mean": dur / max(fwd + bwd, 1),
        "flow_iat_std": 100.0,
        "flow_iat_max": dur,
        "flow_iat_min": 1.0,
        "fwd_iat_total": dur * 0.5,
        "fwd_iat_mean": dur / max(fwd, 1),
        "fwd_iat_std": 50.0,
        "fwd_iat_max": dur,
        "fwd_iat_min": 1.0,
        "bwd_iat_total": dur * 0.4,
        "bwd_iat_mean": dur / max(bwd, 1),
        "bwd_iat_std": 60.0,
        "bwd_iat_max": dur,
        "bwd_iat_min": 1.0,
        "fwd_psh_flags": 1.0,
        "bwd_psh_flags": 1.0,
        "fwd_urg_flags": 0.0,
        "bwd_urg_flags": 0.0,
        "fin_flag_count": 1.0,
        "syn_flag_count": syn,
        "rst_flag_count": 0.0,
        "psh_flag_count": float(fwd),
        "ack_flag_count": float(bwd),
        "urg_flag_count": 0.0,
        "fwd_header_len": float(fwd * 20),
        "bwd_header_len": float(bwd * 20),
        "fwd_avg_bytes_per_bulk": 80.0,
        "bwd_avg_bytes_per_bulk": 150.0,
        "init_win_bytes_forward": 29200.0,
        "init_win_bytes_backward": 28960.0,
        "active_mean": dur * 0.1,
        "active_std": 0.0,
        "idle_mean": dur * 0.8,
        "idle_std": 0.0,
        "down_up_ratio": float(bwd) / float(fwd) if fwd > 0 else 0.0,
        "timestamp": timestamp,
    })

# Schema features with no column in the CICIDS2017 CSVs. They are zero for every training row (zero
# variance, zero importance in the shipped models), so their absence is expected and only logged.
KNOWN_ABSENT_FEATURES = ("time_of_day_sin", "time_of_day_cos")
# Computed below when the column is absent.
DERIVED_FEATURES = ("payload_entropy",)


def prepare_features(df: pd.DataFrame, max_missing=None):
    """
    Maps a raw flow DataFrame onto FEATURE_NAMES. Columns that cannot be found are filled with 0.0 and
    reported. With max_missing set (training/evaluation), more than that many unexpectedly missing
    schema features raises instead of silently producing all-zero columns: a renamed CSV header would
    otherwise train a model on a dead feature without any warning.
    """
    # Strip column names whitespace and try matching case insensitively if exact match fails
    clean_cols = {c.strip(): c for c in df.columns}
    zero_filled = []
    
    X_dict = {}
    for fn in FEATURE_NAMES:
        found = False
        if fn in CANDIDATES:
            for cand in CANDIDATES[fn]:
                # Check for exact stripped match
                if cand in clean_cols:
                    X_dict[fn] = pd.to_numeric(df[clean_cols[cand]], errors='coerce').fillna(0.0)
                    found = True
                    break
                # Try lowercase stripped match
                cand_lower = cand.lower().replace("_", "").replace(" ", "").replace("/", "")
                for col_stripped, orig_col in clean_cols.items():
                    col_norm = col_stripped.lower().replace("_", "").replace(" ", "").replace("/", "")
                    if col_norm == cand_lower:
                        X_dict[fn] = pd.to_numeric(df[orig_col], errors='coerce').fillna(0.0)
                        found = True
                        break
                if found:
                    break
        if not found:
            # check directly
            if fn in clean_cols:
                X_dict[fn] = pd.to_numeric(df[clean_cols[fn]], errors='coerce').fillna(0.0)
            else:
                X_dict[fn] = pd.Series(0.0, index=df.index)
                if fn not in DERIVED_FEATURES:
                    zero_filled.append(fn)
                
    # Fallback/dynamic calculations
    # 1. payload_entropy calculation on-the-fly
    if "payload_entropy" not in clean_cols:
        fwd_len = X_dict.get("total_len_fwd_packets", pd.Series(0.0, index=df.index))
        bwd_len = X_dict.get("total_len_bwd_packets", pd.Series(0.0, index=df.index))
        total = fwd_len + bwd_len
        
        p_f = fwd_len / total
        p_b = bwd_len / total
        entropy = pd.Series(0.0, index=df.index)
        
        mask_f = (total > 0.0) & (p_f > 0.0)
        entropy[mask_f] -= p_f[mask_f] * np.log2(p_f[mask_f])
        
        mask_b = (total > 0.0) & (p_b > 0.0)
        entropy[mask_b] -= p_b[mask_b] * np.log2(p_b[mask_b])
        X_dict["payload_entropy"] = entropy
        
    unexpected = [fn for fn in zero_filled if fn not in KNOWN_ABSENT_FEATURES]
    if unexpected:
        _features_log.warning("prepare_features: %d schema feature(s) not found and zero-filled: %s",
                              len(unexpected), ", ".join(unexpected))
        if max_missing is not None and len(unexpected) > max_missing:
            raise ValueError(f"Training data is missing {len(unexpected)} schema features "
                             f"(allowed {max_missing}): {', '.join(unexpected)}")

    X = pd.DataFrame(X_dict)[FEATURE_NAMES]
    X = X.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    
    # Label mapping logic
    label_col = None
    for c in ["label", "Label"]:
        for col_stripped, orig_col in clean_cols.items():
            if col_stripped.lower() == c.lower():
                label_col = orig_col
                break
        if label_col:
            break
            
    if label_col:
        s_lbls = df[label_col].astype(str).str.strip()
        mapped = s_lbls.map(lambda x: RAW_LABEL_TO_TARGET.get(x, x))
        y = mapped.map(LABEL_MAP).fillna(0).astype(int)
    else:
        y = pd.Series(0, index=df.index).astype(int)
        
    return X.values, y.values

def log_transform_features(X):
    # Flow Duration is column 0
    # Flow Bytes/s is column 13
    # Flow Packets/s is column 14
    import numpy as np
    X_copy = X.copy()
    X_copy[:, 0] = np.log1p(np.maximum(0.0, X_copy[:, 0]))
    X_copy[:, 13] = np.log1p(np.maximum(0.0, X_copy[:, 13]))
    X_copy[:, 14] = np.log1p(np.maximum(0.0, X_copy[:, 14]))
    return X_copy


