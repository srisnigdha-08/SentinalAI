#!/usr/bin/env python3
"""
verify_protected_hashes.py
Completely read-only utility to compute full SHA-256 hashes, file sizes, and
mtimes for all protected artifacts defined in GATE1_CONTRACT.md.

Outputs machine-readable JSON. Never writes to, creates, or modifies any protected file.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

# Contract baselines from GATE1_CONTRACT.md Section 1
CONTRACT_BASELINES = {
    "ai-engine/models/rf_classifier_cicids_v2.pkl": {
        "expected_sha256": "CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1",
        "description": "Seed random forest model v2",
        "notes": "Historical baseline from GATE1_CONTRACT.md"
    },
    "ai-engine/models/isolation_forest_cicids.pkl": {
        "expected_sha256": "17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4",
        "description": "Isolation forest anomaly model",
        "notes": "Historical baseline from GATE1_CONTRACT.md"
    },
    "ai-engine/models/xgb_classifier_cicids_v2.pkl": {
        "expected_sha256": "A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D",
        "description": "XGBoost classifier model v2",
        "notes": "Protected model in models/; baseline recorded in Step 1 preflight"
    },
    "ai-engine/models/q_table.json": {
        "expected_sha256": "BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF",
        "description": "Seed Q-table baseline",
        "notes": "Historical baseline from GATE1_CONTRACT.md"
    },
    "ai-engine/runtime/q_table.json": {
        "expected_sha256": "5242A6496FA3E8EB00B101E9C3C24F354FDB849A1C5042686E207384B0F326E6",
        "description": "Runtime Q-table",
        "notes": "Pre-Phase-12 contract baseline. Incident state in Step 1 is 08209E9989189BD45B6EDF35486A446F120DF36287A277A9DDDD35F6379152F7"
    },
    "ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl": {
        "expected_sha256": "71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020",
        "description": "Phase 8 multi-corpus candidate RF model v1",
        "notes": "Historical baseline from GATE1_CONTRACT.md"
    },
    "ai-engine/experiments/gate1_phase10_detector_recovery/candidate_rf_multicorpus_v2_fixed.pkl": {
        "expected_sha256": "F83C1F878E55EAEEE60E8E266DC17EA34876FA467BEE56900BB4533DE08354C2",
        "description": "Phase 10 detector recovery candidate RF model v2 fixed",
        "notes": "Historical baseline from GATE1_CONTRACT.md"
    }
}


def find_repo_root() -> Path:
    current = Path(__file__).resolve().parent
    for _ in range(5):
        if (current / "GATE1_CONTRACT.md").exists() or (current / ".git").exists():
            return current
        current = current.parent
    return Path.cwd().resolve()


def compute_file_hash_and_metadata(path: Path) -> dict:
    if not path.exists():
        return {
            "exists": False,
            "size_bytes": None,
            "mtime_iso": None,
            "sha256": None,
            "error": "File does not exist"
        }
    
    stat = path.stat()
    mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
    size = stat.st_size
    
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
            
    sha256_upper = hasher.hexdigest().upper()
    
    return {
        "exists": True,
        "size_bytes": size,
        "mtime_iso": mtime,
        "sha256": sha256_upper,
        "error": None
    }


def verify_all_protected(repo_root: Path, baseline_compare: dict = None) -> dict:
    results = {}
    mismatches = 0
    drift_count = 0
    
    timestamp_iso = datetime.now(timezone.utc).isoformat()
    
    for rel_path, meta in CONTRACT_BASELINES.items():
        full_path = repo_root / rel_path
        file_info = compute_file_hash_and_metadata(full_path)
        
        expected = meta["expected_sha256"]
        if not file_info["exists"]:
            status = "MISSING"
            mismatches += 1
        elif expected is None:
            status = "NO_HISTORICAL_BASELINE"
        elif file_info["sha256"] == expected:
            status = "MATCH"
        else:
            status = "DIFFERENT"
            mismatches += 1
            
        entry = {
            "relative_path": rel_path,
            "absolute_path": str(full_path),
            "description": meta["description"],
            "notes": meta["notes"],
            "expected_sha256": expected,
            "current_sha256": file_info["sha256"],
            "size_bytes": file_info["size_bytes"],
            "mtime_iso": file_info["mtime_iso"],
            "status": status
        }
        
        if baseline_compare and rel_path in baseline_compare.get("artifacts", {}):
            base_sha = baseline_compare["artifacts"][rel_path].get("current_sha256")
            if base_sha != file_info["sha256"]:
                entry["drift_from_baseline"] = True
                entry["baseline_sha256"] = base_sha
                drift_count += 1
            else:
                entry["drift_from_baseline"] = False
                entry["baseline_sha256"] = base_sha
                
        results[rel_path] = entry
        
    return {
        "timestamp_iso": timestamp_iso,
        "repo_root": str(repo_root),
        "total_protected_files": len(CONTRACT_BASELINES),
        "contract_baseline_matches": sum(1 for e in results.values() if e["status"] == "MATCH"),
        "contract_baseline_different": sum(1 for e in results.values() if e["status"] == "DIFFERENT"),
        "contract_baseline_missing": sum(1 for e in results.values() if e["status"] == "MISSING"),
        "drift_detected_count": drift_count,
        "artifacts": results
    }


def main():
    parser = argparse.ArgumentParser(description="Verify hashes of protected SentinelAI artifacts.")
    parser.add_argument("--repo-root", type=str, default=None, help="Path to repo root")
    parser.add_argument("--output", type=str, default=None, help="Save machine-readable JSON to file")
    parser.add_argument("--compare-baseline", type=str, default=None, help="Path to preflight JSON to compare for drift")
    args = parser.parse_args()
    
    repo_root = Path(args.repo_root).resolve() if args.repo_root else find_repo_root()
    
    baseline_data = None
    if args.compare_baseline:
        with open(args.compare_baseline, "r") as f:
            baseline_data = json.load(f)
            
    summary = verify_all_protected(repo_root, baseline_compare=baseline_data)
    
    json_str = json.dumps(summary, indent=2)
    if args.output:
        out_p = Path(args.output).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"Results written to {out_p}")
    else:
        print(json_str)


if __name__ == "__main__":
    main()
