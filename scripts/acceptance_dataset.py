"""Select real archived flows for isolated native acceptance, never generate features."""
from pathlib import Path
import json
import sys
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai-engine"))
from utils.features import prepare_features, FEATURE_NAMES

samples = []
for filename, label in [("Monday-WorkingHours.pcap_ISCX.csv", "BENIGN"),
                        ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "DDoS")]:
    for chunk in pd.read_csv(ROOT / "ai-engine/datasets/cicids2017" / filename, chunksize=10000):
        column = next(c for c in chunk if c.strip().lower() == "label")
        selected = chunk[chunk[column].astype(str).str.strip() == label].head(16)
        if selected.empty:
            continue
        features, _ = prepare_features(selected)
        for index, vector in zip(selected.index, features):
            record = dict(zip(FEATURE_NAMES, vector.tolist()))
            record.update(sourceIP="192.0.2.10" if label == "BENIGN" else "192.0.2.20",
                          acceptanceTest=True,
                          provenance={"dataset": filename, "rowIndex": int(index), "label": label,
                                      "sourceAddress": "documentation-only acceptance identifier"})
            samples.append(record)
        break
Path(sys.argv[1]).write_text(json.dumps(samples, indent=2, allow_nan=False), encoding="utf-8")
print(f"Prepared {len(samples)} real dataset rows with provenance for the dedicated acceptance database")
