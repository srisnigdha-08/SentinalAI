# Isolated CICIDS evaluation

Start the native AI engine as described in
[the native guide](../../docs/NATIVE_DEVELOPMENT.md). Set SENTINEL_KEY for the
replay process, then run from ai-engine:

```powershell
.venv/Scripts/python.exe demo/replay_cicids.py --file datasets/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --rows 10 --delay 1.5
```

The script uses /predict/eval. It evaluates historical dataset records without
adding production alerts, changing counters, persisting predictions, or blocking
IPs. Scores and decisions are model outputs; no guaranteed detection rate or
forced BLOCK result is claimed. It requires the provided dataset and real models.
