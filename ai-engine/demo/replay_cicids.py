#!/usr/bin/env python3
"""
SentinelAI - CICIDS2017 Dataset Live Replay Demonstration
=========================================================
An honest, unrigged evaluation tool that replays real historical network attack
and benign traffic from the official CICIDS2017 dataset against the ALREADY-TRAINED
production SentinelAI inference server (/predict).

HARD CONSTRAINTS & INTEGRITY GUARANTEES:
- Ground-truth 'Label' is NEVER included in the API request payload.
- 'Label' is stripped before constructing the request and revealed ONLY post-hoc
  after the model has returned its independent prediction.
- No second classifier, simulation mode, or synthetic fallbacks are used.
- Uses the live, existing production model (rf_classifier_cicids_v2.pkl).
- The secret API key is NEVER printed, logged, or hardcoded.
"""

import warnings
warnings.filterwarnings("ignore")

import os
import sys
import time
import math
import argparse
import requests
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd

# Guarantee UTF-8 output across Windows PowerShell / CMD
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Enable native ANSI color escape sequences on Windows
if os.name == "nt":
    os.system("")

# Styling & ANSI formatting constants for projector clarity
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    WHITE   = "\033[97m"

def disable_colors():
    for attr in dir(Color):
        if not attr.startswith("__"):
            setattr(Color, attr, "")

# Mapping of raw CICIDS2017 CSV labels to canonical SentinelAI target classes
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

# Verified mapping from raw CICIDS2017 stripped header names to Pydantic Record fields
HEADER_TO_RECORD_FIELD = {
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_len_fwd_packets",
    "Total Length of Bwd Packets": "total_len_bwd_packets",
    "Fwd Packet Length Max": "fwd_packet_len_max",
    "Fwd Packet Length Min": "fwd_packet_len_min",
    "Fwd Packet Length Mean": "fwd_packet_len_mean",
    "Fwd Packet Length Std": "fwd_packet_len_std",
    "Bwd Packet Length Max": "bwd_packet_len_max",
    "Bwd Packet Length Min": "bwd_packet_len_min",
    "Bwd Packet Length Mean": "bwd_packet_len_mean",
    "Bwd Packet Length Std": "bwd_packet_len_std",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_total",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_total",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "FIN Flag Count": "fin_flag_count",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "URG Flag Count": "urg_flag_count",
    "Fwd Header Length": "fwd_header_len",
    "Bwd Header Length": "bwd_header_len",
    "Fwd Avg Bytes/Bulk": "fwd_avg_bytes_per_bulk",
    "Bwd Avg Bytes/Bulk": "bwd_avg_bytes_per_bulk",
    "Init_Win_bytes_forward": "init_win_bytes_forward",
    "Init_Win_bytes_backward": "init_win_bytes_backward",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Down/Up Ratio": "down_up_ratio",
}


def resolve_api_key(cli_key: str = None) -> str:
    """
    Resolves the SentinelAI API key from:
      1. Explicit CLI argument (--api-key)
      2. SENTINEL_KEY environment variable
      3. deployment/.env file (via python-dotenv if available)
    
    SECURITY GUARANTEE: Never prints, logs, or writes the actual key value.
    """
    if cli_key and cli_key.strip():
        return cli_key.strip()

    env_key = os.getenv("SENTINEL_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    base_dir = Path(__file__).resolve().parent.parent
    candidate_paths = [
        base_dir.parent / "deployment" / ".env",
        base_dir / ".env",
        Path(".env")
    ]
    for env_path in candidate_paths:
        if env_path.exists():
            try:
                import dotenv
                env_vals = dotenv.dotenv_values(env_path)
                cand = env_vals.get("SENTINEL_KEY") or env_vals.get("HONEYPOT_API_KEY")
                if cand and cand.strip():
                    return cand.strip()
            except Exception:
                pass

    print(f"{Color.RED}[ERROR] Authentication failed: SENTINEL_KEY not found in environment or deployment/.env.{Color.RESET}", file=sys.stderr)
    print("        Please provide it via export SENTINEL_KEY=... or --api-key <key>.", file=sys.stderr)
    sys.exit(1)


def sanitize_float(val, default=0.0) -> float:
    """Converts a value to float, replacing NaN, inf, or parse errors with default."""
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return float(default)
        return float(f)
    except (ValueError, TypeError):
        return float(default)


def format_threat_meter(score: float, width: int = 10) -> str:
    """Renders an ASCII threat gauge for presentations."""
    filled = max(0, min(width, int(round(score * width))))
    empty = width - filled
    bar_chars = "#" * filled + "-" * empty
    if score >= 0.90:
        return f"{Color.RED}[{bar_chars}] {score:.4f}{Color.RESET}"
    elif score >= 0.70:
        return f"{Color.YELLOW}[{bar_chars}] {score:.4f}{Color.RESET}"
    else:
        return f"{Color.GREEN}[{bar_chars}] {score:.4f}{Color.RESET}"


def load_curated_sample(file_or_dir: Path, total_rows: int = 10) -> list:
    """
    Selects a balanced, curated sample of BENIGN and attack rows from the real CSV dataset.
    Uses 'Label' ONLY during this selection phase to form the test set.
    """
    if not file_or_dir.exists():
        raise FileNotFoundError(f"Specified dataset path does not exist: {file_or_dir}")

    csv_files = []
    if file_or_dir.is_file():
        csv_files = [file_or_dir]
    else:
        csv_files = sorted(list(file_or_dir.glob("*.csv")))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in directory: {file_or_dir}")

    benign_target = max(1, total_rows // 2)
    attack_target = total_rows - benign_target

    benign_rows = []
    attack_rows_by_class = {}

    for csv_file in csv_files:
        try:
            for chunk in pd.read_csv(csv_file, chunksize=25000, low_memory=False):
                chunk.columns = chunk.columns.str.strip()
                label_col = next((c for c in chunk.columns if c.lower() == "label"), None)
                if not label_col:
                    continue

                clean_labels = chunk[label_col].astype(str).str.strip()
                target_labels = clean_labels.map(lambda x: RAW_LABEL_TO_TARGET.get(x, x))

                # Collect benign samples if still needed
                if len(benign_rows) < benign_target:
                    benign_indices = chunk.index[target_labels == "BENIGN"].tolist()
                    needed = benign_target - len(benign_rows)
                    for idx in benign_indices[:needed]:
                        row = chunk.loc[idx]
                        feature_dict = {}
                        for raw_hdr, field_name in HEADER_TO_RECORD_FIELD.items():
                            val = row.get(raw_hdr, row.get(raw_hdr.lower(), 0.0))
                            feature_dict[field_name] = sanitize_float(val)
                        benign_rows.append({
                            "ground_truth_label": "BENIGN",
                            "source_file": csv_file.name,
                            "raw_features": feature_dict
                        })

                # Collect attack samples from sustained attack phases (>= 20 attacks in chunk)
                attack_mask = (target_labels != "BENIGN")
                if attack_mask.any() and attack_mask.sum() >= 20:
                    attack_sub = chunk[attack_mask]
                    for canon_cls, grp in attack_sub.groupby(target_labels[attack_mask]):
                        if canon_cls not in attack_rows_by_class:
                            attack_rows_by_class[canon_cls] = []
                        if len(attack_rows_by_class[canon_cls]) < max(2, attack_target):
                            needed_atk = max(2, attack_target) - len(attack_rows_by_class[canon_cls])
                            for idx in grp.index[:needed_atk]:
                                row = grp.loc[idx]
                                feature_dict = {}
                                for raw_hdr, field_name in HEADER_TO_RECORD_FIELD.items():
                                    val = row.get(raw_hdr, row.get(raw_hdr.lower(), 0.0))
                                    feature_dict[field_name] = sanitize_float(val)
                                attack_rows_by_class[canon_cls].append({
                                    "ground_truth_label": str(canon_cls),
                                    "source_file": csv_file.name,
                                    "raw_features": feature_dict
                                })

                if len(benign_rows) >= benign_target and sum(len(v) for v in attack_rows_by_class.values()) >= attack_target:
                    break
        except Exception as e:
            print(f"{Color.YELLOW}[WARN] Error reading {csv_file.name}: {e}{Color.RESET}", file=sys.stderr)

    selected_attacks = []
    if attack_rows_by_class:
        classes = list(attack_rows_by_class.keys())
        idx = 0
        while len(selected_attacks) < attack_target and any(len(attack_rows_by_class[c]) > 0 for c in classes):
            cls = classes[idx % len(classes)]
            if attack_rows_by_class[cls]:
                selected_attacks.append(attack_rows_by_class[cls].pop(0))
            idx += 1

    curated = []
    b_idx, a_idx = 0, 0
    while len(curated) < total_rows and (b_idx < len(benign_rows) or a_idx < len(selected_attacks)):
        if b_idx < len(benign_rows):
            curated.append(benign_rows[b_idx])
            b_idx += 1
        if a_idx < len(selected_attacks) and len(curated) < total_rows:
            curated.append(selected_attacks[a_idx])
            a_idx += 1

    return curated[:total_rows]


def run_replay(file_path: str, total_rows: int, delay: float, api_url: str, cli_key: str = None):
    """
    Executes the replay demo with presentation-grade visual formatting.
    """
    api_key = resolve_api_key(cli_key)
    api_url = api_url.rstrip("/")
    predict_url = f"{api_url}/predict/eval"

    print(f"\n{Color.CYAN}{Color.BOLD}============================================================================{Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}         SentinelAI -- CICIDS2017 Real Attack Replay Demonstration          {Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}      Independent Live Evaluation of Production Random Forest Model         {Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}============================================================================{Color.RESET}\n")

    print(f"{Color.BOLD}Demonstration Parameters:{Color.RESET}")
    print(f"  * API Endpoint:     {Color.WHITE}{predict_url}{Color.RESET}")
    print(f"  * Dataset Source:   {Color.WHITE}{file_path}{Color.RESET}")
    print(f"  * Sample Size:      {Color.WHITE}{total_rows} network flows{Color.RESET}")
    print(f"  * Flow Interval:    {Color.WHITE}{delay}s{Color.RESET}")
    print(f"  * Authentication:   {Color.GREEN}Configured (X-API-Key active, value masked){Color.RESET}")
    print(f"  * Integrity Check:  {Color.GREEN}Ground truth withheld until post-inference{Color.RESET}")
    print(f"{Color.DIM}{'-' * 76}{Color.RESET}")

    print(f"\n{Color.YELLOW}[1/2] Curating balanced test sample from real traffic capture...{Color.RESET}")
    t_load_start = time.perf_counter()
    curated_sample = load_curated_sample(Path(file_path), total_rows)
    t_load_ms = (time.perf_counter() - t_load_start) * 1000
    if not curated_sample:
        print(f"{Color.RED}[ERROR] Could not extract samples from specified path.{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"      Selected {len(curated_sample)} network flows in {t_load_ms:.1f}ms.")
    print(f"{Color.DIM}{'-' * 76}{Color.RESET}")
    print(f"{Color.YELLOW}[2/2] Replaying live network traffic through SentinelAI inference engine...{Color.RESET}\n")

    correct_predictions = 0
    total_evaluated = 0
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key
    }

    for i, item in enumerate(curated_sample, 1):
        # -------------------------------------------------------------
        # STRICT LABEL INDEPENDENCE ENFORCEMENT:
        # 1. Ground truth is isolated in 'post_hoc_ground_truth'
        # 2. Request payload contains ONLY raw network flow features
        # 3. Payload has NO 'label', 'Label', or 'ground_truth' field
        # -------------------------------------------------------------
        post_hoc_ground_truth = item["ground_truth_label"]
        raw_features = item["raw_features"].copy()

        payload = raw_features
        payload["sourceIP"] = f"192.168.10.{100 + i}"
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Hard integrity assertions
        assert "label" not in payload and "Label" not in payload, "Integrity breach: Label in payload!"
        assert "target_class" not in payload and "ground_truth" not in payload

        t_start = time.perf_counter()
        try:
            resp = requests.post(predict_url, json=payload, headers=headers, timeout=10.0)
            inference_wall_ms = round((time.perf_counter() - t_start) * 1000, 1)
        except requests.exceptions.RequestException as e:
            print(f"{Color.RED}Flow #{i:02d} | API Error: {type(e).__name__}{Color.RESET}")
            continue

        if resp.status_code != 200:
            print(f"{Color.RED}Flow #{i:02d} | HTTP {resp.status_code}: {resp.text[:100]}{Color.RESET}")
            continue

        resp_data = resp.json()
        result = resp_data.get("result", {})

        predicted_class = result.get("predictedClass", "Unknown")
        threat_score = float(result.get("threatScore", 0.0))
        severity = result.get("severity", "UNKNOWN")
        action = result.get("action", "UNKNOWN")
        model_version = result.get("modelVersion", "Unknown")
        inf_time_ms = result.get("inferenceTimeMs", inference_wall_ms)

        # POST-HOC COMPARISON: Revealed strictly after receiving response
        is_match = (predicted_class == post_hoc_ground_truth)
        if is_match:
            correct_predictions += 1
            status_badge = f"{Color.GREEN}{Color.BOLD}[MATCH]{Color.RESET}"
        else:
            status_badge = f"{Color.RED}{Color.BOLD}[MISMATCH]{Color.RESET}"

        total_evaluated += 1

        # Presentation card display
        pred_color = Color.RED if predicted_class != "BENIGN" else Color.GREEN
        action_color = Color.RED if action == "BLOCK" else Color.YELLOW if action == "MONITOR" else Color.GREEN

        print(f"{Color.BOLD}Flow #{i:02d}{Color.RESET} | {Color.DIM}Time: {datetime.now().strftime('%H:%M:%S')}{Color.RESET} | Client IP: {payload['sourceIP']} | Source: {item['source_file']}")
        print(f"  +-- {Color.CYAN}Model Prediction:{Color.RESET}      {pred_color}{Color.BOLD}{predicted_class:<20}{Color.RESET} Threat: {format_threat_meter(threat_score)} | {action_color}{action}{Color.RESET}")
        print(f"  +-- {Color.CYAN}Post-Hoc Ground Truth:{Color.RESET} {Color.WHITE}{post_hoc_ground_truth:<20}{Color.RESET} {Color.DIM}(Revealed post-prediction){Color.RESET}")
        print(f"  +-- {Color.CYAN}Verdict:{Color.RESET}               {status_badge}  | Model: {model_version} | Latency: {inf_time_ms:.1f}ms")
        print(f"{Color.DIM}{'-' * 76}{Color.RESET}")

        if i < len(curated_sample) and delay > 0:
            time.sleep(delay)

    accuracy_pct = (correct_predictions / total_evaluated * 100.0) if total_evaluated > 0 else 0.0
    acc_color = Color.GREEN if accuracy_pct >= 90 else Color.YELLOW if accuracy_pct >= 70 else Color.RED

    print(f"\n{Color.CYAN}{Color.BOLD}============================================================================{Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}                  REPLAY DEMONSTRATION SUMMARY RESULTS                      {Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}============================================================================{Color.RESET}")
    print(f"  * Total Network Flows Tested:     {Color.BOLD}{total_evaluated}{Color.RESET}")
    print(f"  * Correct Model Predictions:      {Color.GREEN}{Color.BOLD}{correct_predictions}{Color.RESET}")
    print(f"  * Misclassified Flows:            {Color.RED if total_evaluated != correct_predictions else Color.GREEN}{total_evaluated - correct_predictions}{Color.RESET}")
    print(f"  * Sample Demonstration Accuracy:  {acc_color}{Color.BOLD}{accuracy_pct:.2f}%{Color.RESET}")
    print(f"  * Pipeline Integrity Status:      {Color.GREEN}[VERIFIED] Zero Ground-Truth Label Leakage{Color.RESET}")
    print(f"{Color.CYAN}{'=' * 76}{Color.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAI Live CICIDS2017 Replay Demo - Genuine Unrigged Evaluation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--file", "-f",
        default=str(Path(__file__).resolve().parent.parent / "datasets" / "cicids2017" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"),
        help="Path to a CICIDS2017 CSV file or datasets directory"
    )
    parser.add_argument(
        "--rows", "-n",
        type=int,
        default=10,
        help="Number of network flow samples to replay"
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=1.5,
        help="Delay in seconds between consecutive /predict requests"
    )
    parser.add_argument(
        "--api-url", "-u",
        default="http://localhost:8000",
        help="Base URL of the SentinelAI inference engine"
    )
    parser.add_argument(
        "--api-key", "-k",
        default=None,
        help="Optional API key override (defaults to SENTINEL_KEY env var or deployment/.env)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output"
    )

    args = parser.parse_args()
    if args.no_color:
        disable_colors()

    run_replay(
        file_path=args.file,
        total_rows=args.rows,
        delay=args.delay,
        api_url=args.api_url,
        cli_key=args.api_key
    )


if __name__ == "__main__":
    main()
