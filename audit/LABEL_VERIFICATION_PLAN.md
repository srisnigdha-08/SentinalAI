# Label verification plan: 2017-Thursday probe flows (DATA-005), pre-registered 2026-11-02

Nothing in this plan relabels data, trains a model or touches the protected 2018 days. It defines how to decide,
from evidence independent of any model, whether the 63,022 BENIGN-labelled probe flows in
`Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` are the dataset's own scheduled port scan.

## 1. What is known (from `ML_DEV_RESULTS.md`, Thursday section)

- Signature: forward initial window 1024, ≤ 2 packets each way, no backward window.
- In the Friday PortScan file, 77,984 of 77,987 signature rows are labelled PortScan. In the Thursday afternoon
  file, all 63,022 are labelled BENIGN; they cover 1,001 ports and sit at 40–75 % of the file, inside the span of
  the 36 "Infiltration" rows.
- 823 of C4-A's 920 Thursday false positives are this signature, and every candidate including C0 has about 900
  false positives on that fold.

## 2. Independent reference: the dataset authors' attack schedule

The CIC IDS2017 page ([unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)) lists, for
Thursday 6 July 2017, "Dropbox download on Win Vista" from 15:04 to 15:45 in two steps. The second step is a
"Portscan + Nmap" phase with the Windows Vista host **192.168.10.8 as attacker** and all other clients as victims.
The schedule was written by the dataset authors, independently of our models and features, which is why it can serve
as ground truth for this check.

## 3. Data needed

| Item | Source | Size | Who |
|---|---|---|---|
| `GeneratedLabelledFlows.zip` (same flows as our CSVs, plus Flow ID, Source/Destination IP and port, Timestamp) | CIC download page, `cicresearch.ca/CICDataset/CIC-IDS-2017/`; requires a registration form (name, email, organisation, country) | not shown on the page; to be noted when downloaded | **you**: I will not fill in the form with your personal details |

Only the one Thursday-afternoon CSV from the archive is needed. Suggested location, outside the repository:
`D:\sentinelai_datasets\cicids2017_labelled\` (create it fresh and extract only that file there). Citation as
required by CIC: Sharafaldin, Habibi Lashkari, Ghorbani, ICISSP 2018. PCAPs (Thursday 7.8 GB) are **not** needed
unless the CSV check is inconclusive.

## 4. Procedure (read-only; `ai-engine/evaluation/verify_labels_2017.py`, tests in `tests/test_dev_protocol_v2.py`)

1. **Join.** The script aligns the labelled file row by row with our MachineLearningCVE file. Both are CICFlowMeter
   output of the same capture; the check compares eight columns: destination port, duration, packet counts, both
   initial windows, forward bytes and label. If fewer than 99 % of rows agree, the result is **INCONCLUSIVE**. No
   fuzzy matching is attempted, and the PCAP route would need a separate plan.
2. **Select** the probe-signature rows with the same function as the analysis (`probe_signature`).
3. **Decide** with the rule fixed in the script before the file is obtained:
   - (a) ≥ 95 % of the rows have 192.168.10.8 as source or destination IP;
   - (b) ≥ 95 % are timestamped 15:00–15:50 (the schedule ± 5 min; CIC's 12-hour times without AM/PM are read as
     afternoon);
   - (c) the other endpoint covers ≥ 3 distinct 192.168.10.x hosts.

   All three must hold for **VERIFIED**; otherwise the result is **NOT VERIFIED**. The report also gives per-row
   counts, top IPs, the time range and the source IPs of the 36 "Infiltration" rows, whatever the verdict.
4. **Output:** `ai-engine/experiments/label_verification_<date>/thursday_label_verification.json`. Expected runtime is
   under 2 minutes, with nothing written outside `experiments/`.

## 5. What each outcome leads to (decided now, before the result)

| Outcome | Consequence |
|---|---|
| VERIFIED | A new protocol version (v3) may define a label correction: rows meeting all three conditions are treated as PortScan in training and test for **every** candidate, C0 included. All results are then reported under both the published and the corrected labels. v3 must state that it was written after these results were seen. No existing result is edited. Re-running C0 and the candidates under v3 is training and needs your approval. |
| NOT VERIFIED | Labels stay as published. DATA-005 is recorded as an unexplained pattern. The 2017-Thursday fold stays as it is, and C4-A-I is judged under the unchanged v1 rule. |
| INCONCLUSIVE | No change. Options (PCAP-based check, about 7.8 GB) are described with their cost and need separate approval. |

The §7 thresholds (FPR ≤ C0 + 0.1 pp, ≤ 2 % per fold, +10 points recall) are not part of this plan and do not change
in any outcome.

## 6. Out of scope

- 21-02-2018 (DATA-004): the processed 2018 CSVs have no IPs, and the 2018 PCAPs are large; a separate plan would be
  needed. The finding stays as a hypothesis.
- Any other 2017 or 2018 label.
- The four protected 2018 days.

## 7. Approval requested

1. **You:** download `GeneratedLabelledFlows.zip` through the CIC form and extract only
   `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` to a new folder, for example
   `D:\sentinelai_datasets\cicids2017_labelled\`.
2. **Me, on your go-ahead:**

   ```powershell
   cd ai-engine
   .venv\Scripts\python evaluation\verify_labels_2017.py --labelled D:\sentinelai_datasets\cicids2017_labelled\Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
   ```

   This is read-only. No training, no relabelling, no change to models, thresholds or results.

## 8. Outcome (run 2026-11-02): **VERIFIED**

### Data obtained

The CIC download links redirect to a registration form, so the file was not fetched from CIC. You asked me to download
it myself, and it came from a public mirror instead:
- Hugging Face `Mireu-Lab/CIC-IDS`, `ZIP/GeneratedLabelledFlows.zip`, 283,876,488 bytes, sha256 `7bdbef28…a27a`.
- Saved to `D:\sentinelai_datasets\cicids2017_labelled\` (a new folder outside the repository).
- Only `TrafficLabelling/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` was extracted (108,723,183
  bytes, sha256 `d74238e0…2c4b`), written under a fixed file name; nothing in the archive was executed.

The mirror is not CIC's official server and no official hash is published. Its integrity was checked against the
MachineLearningCVE file every experiment uses:
- both have 288,602 rows;
- all eight join columns agree on **100 %** of rows (destination port, duration, packet counts, both initial windows,
  forward bytes, label).

The IP and timestamp columns cannot be authenticated independently of the mirror. Fabricating them consistently with
CIC's published schedule would be implausible, but this remains a stated limitation.

A comparison bug was fixed before the verdict was read:
- The first run reported join agreement 0.0 because one file writes `48` and the other `48.0` in
  `Total Length of Fwd Packets`; every other column agreed 100 %.
- The checker now compares numeric columns numerically (test added).
- The decision rule and thresholds were not touched.

### Result (`ai-engine/experiments/label_verification_20261102/thursday_label_verification.json`)

| Condition (pre-registered) | Threshold | Observed | Pass |
|---|---|---|---|
| join agreement | ≥ 99 % | 100 % | yes |
| (a) 192.168.10.8 as source or destination | ≥ 95 % | **98.4 %** (62,026 rows; 975 via 172.16.0.1, the firewall) | yes |
| (b) timestamp 15:00–15:50 | ≥ 95 % | **95.3 %**, a narrow pass | yes |
| (c) distinct internal peers | ≥ 3 | **11** (192.168.10.5, .14, .15, .25, .9, …) | yes |

- 60,030 of the 63,022 signature rows meet all three conditions.
- 1,996 signature rows involving 192.168.10.8 are timestamped in hour 14. That is the earlier Meta-exploit phase
  (14:19–14:35), not the scheduled scan, so they **do not** meet the rule.
- All 36 rows labelled "Infiltration" have source 192.168.10.8, the same host.

### Link to the model results (descriptive; no result is edited)

- In the C4-A 2017-Thursday test fold, 816 of the 10,096 pooled afternoon benign rows meet all three conditions.
  C4-A flags **810** of them, which is 795 of its 823 "Port Scan" calls and 810 of its 920 Thursday false positives.
- The other 110 false positives would be **0.52 %** of the remaining 21,109 benign rows.
- This is arithmetic on stored predictions, **not** a v3 result. Under a correction the same rows would also change
  in the training folds, and that needs re-training.

### What follows (as decided in §5)

- Labels in the stored datasets are **not** modified, and v1/v2 results stand as reported.
- A v3 protocol may now define the correction: rows meeting all three conditions are treated as PortScan in training
  and test for every candidate including C0, and results are reported under both label sets. v3 must be written and
  approved before any run.
- §7 thresholds are unchanged.
