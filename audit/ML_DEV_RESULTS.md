# Development results under protocol v1 (`ML_DEV_PROTOCOL.md`)

## Batch 1 — C0, C1, C2 on D17 + D18 (run 2026-11-02, approved)

Command (from `ai-engine/`): `.venv\Scripts\python evaluation\dev_experiments.py --run --approved --candidates C0,C1,C2
--folds D17,D18 --out experiments\dev_20261102_batch1`. Output: `ai-engine/experiments/dev_20261102_batch1/results.json`.
All 33 fold manifests equal the pre-registered `experiments/dev_20261102/plan.json`; throwaway models only;
`models/` and `runtime/` unchanged; the protected 2018 days were not read (not on disk). Fits 3.5–20.5 s per fold.

### Binary decision at the classifier output (mean over folds with attacks; FPR over all folds)

| Candidate | D17 attack recall | D17 benign FPR (mean / max) | D18 attack recall | D18 benign FPR (mean / max) | Eligible (§7)? |
|---|---|---|---|---|---|
| C0 served recipe, 53 features | 19.3 % | 1.54 % / 4.12 % | 11.1 % | 0.37 % / 1.68 % | baseline |
| C1 features C (45; no TCP-window, no constants) | 25.4 % | **5.67 % / 9.43 %** | 14.9 % | **3.16 % / 8.69 %** | **no** — FPR limits (≤ 1.64 % / ≤ 0.47 % mean, ≤ 2 % per fold) |
| C2 two-stage on features C, T1 | 22.8 % | 1.29 % / **4.33 %** | 15.8 % | **2.85 % / 8.60 %** | **no** — fold FPR > 2 %, D18 mean FPR > 0.47 % |

**Pre-registered outcome: no candidate is eligible; nothing is selected from batch 1.** Even ignoring eligibility,
the recall gains (C1 +6.1 / +3.8 points, C2 +3.5 / +4.7) are below the 10-point bar for an external test.

### Per family (rows flagged as any attack / rows; summed over folds)

| Family | 2017 folds: C0 / C1 / C2 | 2018 folds (2017-only training): C0 / C1 / C2 |
|---|---|---|
| DoS/DDoS | 30.0 / 36.0 / **51.1 %** | 40.4 / 45.4 / 44.5 % |
| Brute Force | 4.8 / 8.7 / 0.3 % | 0.8 / 1.4 / 1.2 % |
| Web Attack | 21.8 / **51.4** / 1.2 % | 0 / 23.9 / **38.3 %** |
| Botnet | 0 / 0 / 0 % | 0 / 0.02 / 0.2 % |
| Infiltration | 2.8 / 2.8 / 0 % | 3.6 / 5.0 / 0.8 % |
| Reconnaissance (2017 only) | 13.8 / 17.2 / 16.9 % | — |

Per fold (attack recall, benign FPR, precision, PR-AUC, Brier, µs/row, model size) is in `results.json`.
Latency 3.6–8.1 µs/row in batch; models 1.9–3.7 MB.

### What batch 1 shows

1. **The TCP-window features are not only testbed fingerprints of attackers — they also anchor "normal" for each
   testbed.** Removing them raises recall a little and lets web attacks transfer to 2018 (0 → 24–38 %), but benign
   FPR rises 2–10× (2017 Monday 0.23 → 7.3 %, 2018 23-02 0.15 → 8.7 %). Removing them without a replacement for what
   they gave the benign side is not acceptable.
2. **Binary-first alone does not fix cross-testbed transfer**; it lowers some 2017 FPRs (Friday 2.7 → 0.7 %) but its
   2018 FPR is far above the baseline's.
3. **Training only on CICIDS2017 cannot detect tools it never saw**: 2018 botnet and SSH/FTP/web brute force stay
   at 0–1.4 % for every candidate; DoS transfers only from the GoldenEye/Slowloris day (≈ 62–69 %), HOIC at 0 %.
   This points to **training data diversity (C4)** as the remaining lever, not 2017-only feature or architecture
   changes.
4. The served model stays. No threshold, feature contract or runtime logic was changed.

### Next (needs approval; protocol v1 unchanged)

- **Batch 3 first: C4** (two-stage, features C, T1, 2017 + 2018 development data) — the only candidate that sees more
  than one tool per family. Its D18 folds hold out one 2018 day each, so it is still evaluated on unseen days.
- Batch 2 (C1e, C3, C0rf) is lower priority after these results; C1e adds per-packet headers to C (same FPR risk).
- If C4 also fails §7, protocol v2 would need a new idea (e.g. keep the TCP-window features for the benign side
  only, or per-testbed benign profiles) — pre-registered before any run.

## Batch 3 — C4 (two-stage, features C, T1, 2017 + 2018 development data) on D17 + D18 (run 2026-11-02, approved)

Command: `dev_experiments.py --run --approved --candidates C4 --folds D17,D18 --out experiments\dev_20261102_batch3`.
Output: `ai-engine/experiments/dev_20261102_batch3/results.json`. All 11 manifests equal the plan; throwaway models;
`models/` and `runtime/` unchanged. Fits 8.5–13.2 s; 5.8–9.1 µs/row; 4.0–4.6 MB.

| | D17 recall | D17 FPR mean / max | D18 recall | D18 FPR mean / max |
|---|---|---|---|---|
| C0 baseline | 19.3 % | 1.54 / 4.12 % | 11.1 % | 0.37 / 1.68 % |
| **C4** | **28.7 %** | 1.52 / **4.19 %** | **32.3 %** | **6.45 / 24.3 %** |

**Pre-registered outcome: C4 is not eligible** (a D17 fold above 2 %; D18 mean FPR 6.45 % > 0.47 %; the 21-02 fold
24.3 %). Its recall gain on D18 (+21 points) would clear the 10-point bar, so the limiting factor is false alarms.

Per family (flagged as any attack): 2018 botnet **60.8 %** (C0 0 %), 2018 web attacks **61.2 %** (C0 0 %), 2018 DoS
45.2 % (C0 40.4 %), 2018 brute force 4.4 % (C0 0.8 %), 2018 infiltration 2.3 %; 2017 brute force 28.4 % (C0 4.8 %).

### What batch 3 shows

1. **Diverse training data is the lever that moves recall** — the only candidate so far with a D18 gain above the
   bar. It also reproduces Phase 8's botnet figure (61 %), now with the DATA-002 leak removed.
2. **But it makes benign traffic of a held-out 2018 day look like attacks**: on 21-02 a quarter of benign flows are
   flagged. Not yet explained. Hypotheses (unverified): benign rows inside the HOIC window that are really attack
   traffic (2018 labels are by time/IP window), or benign traffic on that day that resembles other days' attacks.
   This must be examined before any further candidate is designed.
3. Features C were used for C4 (no TCP-window fields). Batch 1 showed those fields keep benign FPR down on 2017;
   combining multi-dataset training with the full feature set (A) is untested.

### Status

No candidate meets §7 after batches 1 and 3; nothing goes to the external test; the served model stays.
Next steps need a protocol **v2**, pre-registered before any run, for example: (a) C4 with features A and with B
(multi-dataset, TCP-window kept); (b) a per-day benign false-positive analysis of the 21-02 fold (which flows, which
predicted class, which feature values) — analysis only, on development data. Batch 2 (C1e, C3, C0rf) is unlikely to
change the conclusion and is deprioritised.

## After batch 3 — analysis only (2026-11-02, no training; protocol v2 in `ML_DEV_PROTOCOL_V2.md`)

v1 results above are unchanged. Macro vs pooled (`evaluation/dev_summary.py`):

| | D18 recall macro / pooled | D18 FPR macro / pooled | worst fold | D18 FPR without 21-02 (macro) |
|---|---|---|---|---|
| C0 | 11.1 / 25.1 % | 0.37 / 0.36 % | 01-03 1.68 % | 0.45 % |
| C1 | 14.9 / 28.5 % | 3.16 / 3.16 % | 23-02 8.69 % | 3.79 % |
| C2 | 15.8 / 27.4 % | 2.85 / 2.86 % | 23-02 8.60 % | 3.42 % |
| C4 | 32.3 / 35.6 % | 6.45 / 6.81 % | 21-02 24.3 % | 2.88 % (15-02 6.98 %) |

21-02-2018: 99.3 % of its benign rows are one flow pattern found on no other day (out of distribution, no duplicates
of training rows, nearest neighbour benign); its FPR is effectively one observation. Even without it C4 is not
eligible. Row-level predictions need the approved v2 batch (`--dump-predictions`).

## Protocol v2, batch 1 — C4 (= C4-C), C4-A, C4-B on D17 + D18 (run 2026-11-02, approved)

Command: `dev_experiments.py --run --approved --dump-predictions --candidates C4,C4A,C4B --folds D17,D18 --out
experiments\dev_20261102_v2batch1` (exit 0, 48 min). Checks: all 33 manifests equal `dev_20261102_v2plan/plan.json`
(and batch 3); **C4 reproduces batch 3 exactly** (tp/fp/fn/tn on all 11 folds); `models/`, `runtime/` unchanged
(git diff empty; classifier `6d08ef19…`, IF `46b16b74…`, golden `c8d72dd9…`, registry `5f76c136…`, Q-table
`08209e99…`); protected days not on disk, not read. **C4-B is identical to C4-A** in every fold and every prediction
(the six features are constant, as verified), so both are reported below as C4-A/B.

### Per fold (binary decision at the classifier; TP/FP/TN/FN)

| Fold | C0 TP/FP/TN/FN | C0 R / FPR / P | C4 TP/FP/TN/FN | C4 R / FPR / P | C4-A/B TP/FP/TN/FN | C4-A/B R / FPR / P |
|---|---|---|---|---|---|---|
| 2017 Mon | 0/28/11994/0 | – / 0.23 / – | 0/75/11947/0 | – / 0.62 / – | 0/30/11992/0 | – / 0.25 / – |
| 2017 Tue | 286/45/11843/8864 | 3.1 / 0.38 / 86.4 | 2940/215/11673/6210 | 32.1 / 1.81 / 93.2 | 138/101/11787/9012 | 1.5 / 0.85 / 57.7 |
| 2017 Wed | 2693/28/11767/5368 | 33.4 / 0.24 / 99.0 | 2126/23/11772/5935 | 26.4 / 0.19 / 98.9 | 6593/45/11750/1468 | 81.8 / 0.38 / 99.3 |
| 2017 Thu | 377/903/21022/1802 | 17.3 / **4.12** / 29.4 | 81/918/21007/2098 | 3.7 / **4.19** / 8.1 | 163/920/21005/2016 | 7.5 / **4.20** / 15.0 |
| 2017 Fri | 2764/967/34756/9027 | 23.4 / **2.71** / 74.1 | 6205/287/35436/5586 | 52.6 / 0.80 / 95.6 | 6332/143/35580/5459 | 53.7 / 0.40 / 97.8 |
| 2018 01-03 | 275/219/12783/7273 | 3.6 / 1.68 / 55.7 | 170/218/12784/7378 | 2.2 / 1.68 / 43.8 | 111/105/12897/7437 | 1.5 / 0.81 / 51.4 |
| 2018 02-03 | 0/19/14224/5610 | 0.0 / 0.13 / – | 3411/500/13743/2199 | 60.8 / **3.51** / 87.2 | 5311/376/13867/299 | 94.7 / **2.64** / 93.4 |
| 2018 14-02 | 43/9/12826/5041 | 0.9 / 0.07 / 82.7 | 100/138/12697/4984 | 2.0 / 1.08 / 42.0 | 3748/53/12782/1336 | 73.7 / 0.41 / 98.6 |
| 2018 15-02 | 11623/24/13065/7224 | 61.7 / 0.18 / 99.8 | 10506/913/12176/8341 | 55.7 / **6.98** / 92.0 | 16447/671/12418/2400 | 87.3 / **5.13** / 96.1 |
| 2018 21-02 | 0/1/14998/9923 | 0.0 / 0.01 / – | 2494/3647/11352/7429 | 25.1 / **24.32** / 40.6 | 484/8/14991/9439 | 4.9 / 0.05 / 98.4 |
| 2018 23-02 | 1/21/13632/540 | 0.2 / 0.15 / 4.5 | 259/157/13496/282 | 47.9 / 1.15 / 62.3 | 308/56/13597/233 | 56.9 / 0.41 / 84.6 |

R = attack recall %, FPR = benign false-positive rate %, P = precision %; bold = fold FPR above 2 %. F1, PR-AUC,
Brier, µs/row and bytes per fold are in `experiments/dev_20261102_v2batch1/results.json`.

### Macro (mean of folds) and pooled (summed counts)

| | D17 recall macro / pooled | D17 FPR macro / pooled / worst | D18 recall macro / pooled | D18 FPR macro / pooled / worst |
|---|---|---|---|---|
| C0 | 19.3 / 19.6 % | 1.53 / 2.11 / 4.12 % (Thu) | 11.1 / 25.1 % | 0.37 / 0.36 / 1.68 % (01-03) |
| C4 | 28.7 / 36.4 % | 1.52 / 1.63 / 4.19 % (Thu) | 32.3 / 35.6 % | 6.45 / 6.81 / 24.32 % (21-02) |
| **C4-A/B** | **36.1 / 42.4 %** | **1.22 / 1.33** / 4.20 % (Thu) | **53.2 / 55.5 %** | **1.58 / 1.55** / 5.13 % (15-02) |

Pooled benign FPs: D17 C0 1,971 → C4 1,518 → C4-A 1,239; D18 C0 293 → C4 5,573 → C4-A 1,269.
Per family on D18 (flagged as attack, summed over folds), C4 → C4-A: botnet 60.8 → 94.7 %, brute force 4.4 → 71.8 %,
web 61.2 → 79.1 %, DoS/DDoS 45.2 → 58.8 %, infiltration 2.3 → 1.5 %.

### Pre-registered outcome (v1 §7, unchanged): **no candidate is eligible**

| | D17 mean FPR ≤ 1.63 % | D17 every fold ≤ 2 % | D18 mean FPR ≤ 0.47 % | D18 every fold ≤ 2 % |
|---|---|---|---|---|
| C4 | yes (1.52) | no (Thu 4.19) | no (6.45) | no (21-02, 15-02, 02-03) |
| C4-A/B | yes (1.22) | no (Thu 4.20) | **no (1.58)** | no (15-02 5.13, 02-03 2.64) |

Nothing goes to the external test; nothing is promoted; the served model stays. The criteria are not relaxed.
An observation, not a change: C0 itself breaks the per-fold 2 % limit on D17 (Thu 4.12 %, Fri 2.71 %), and every
candidate so far has ≥ 4.1 % on 2017 Thursday.

### Does restoring the TCP-window features help? Yes, on every summary measure, but not enough to pass

- Benign FPs fall 77 % on D18 (5,573 → 1,269) and 18 % on D17, while recall **rises** (D18 macro +20.9 points,
  D17 +7.4). Against C0 the D18 recall gain is +42 points (pooled +30).
- The one material recall loss is 21-02: HOIC 30.4 → 5.9 %. C4 caught part of HOIC with the same decision that
  flagged a quarter of that day's benign rows, so C4's 21-02 recall was not a clean gain.
- Latency is **not comparable** to batch 3. The reproduced C4 models (same predictions) measured 36–89 µs/row
  against 5.8–9.1 before, and fits took 55–104 s against 8.5–13 s, so the machine was heavily loaded during this run.
  Model size 3.9–4.5 MB (C0 2.3–3.6 MB; under 2×). Latency must be re-measured on an idle machine before any
  deployment test.

### 21-02 row-level (`evaluation/fp_rows_v2.py`, `v2_rows.json`)

The pool keeps one row per distinct (vector, label), so every pooled row is a distinct vector. "Pattern" below is
the 4-field signature: both initial windows, forward packets, max forward packet length.

| | benign FPs | in the day's dominant pattern | distinct patterns among FPs | predicted class of FPs | p(attack) of FPs (p10 / median / p90) |
|---|---|---|---|---|---|
| C4 | 3,647 / 14,999 | 3,645 (FPR 24.5 % inside the pattern, 1.9 % outside) | 3 | Malware Beacon 2,957, Lateral Movement 689 | 0.68 / 0.81 / 0.89 |
| C4-A/B | 8 / 14,999 | **0** (inside 0 %; outside 7.5 % of 107 rows) | 5 | DDoS 4, Web Brute Force 2, Lateral Movement 2 | 0.52 / 0.57 / 0.69 |

So C4's 21-02 false positives were **one repeated pattern, not 3,647 independent errors**. Features C hide the window
values 65535/32768 from C4, and its remaining features put the pattern next to botnet traffic. With the windows
available, all 14,892 rows of the pattern get p(attack) ≤ 0.07 (benign p99 0.07). This says nothing about whether the
pattern is really benign: the labels are kept as published, and the HOIC-response hypothesis
(`ML_DEV_PROTOCOL_V2.md` §2) remains unverified.

### Where C4-A's remaining false positives come from

- **D18: 1,068 of 1,269 (84 %) are predicted "Lateral Movement"** (the infiltration class): 617 of 671 on 15-02,
  362 of 376 on 02-03, 40/53 on 14-02, 46/56 on 23-02. Their median p(attack) is 0.54–0.59, close to the 0.5 line,
  and they spread over 338 / 106 distinct patterns (not one repeated flow). Meanwhile infiltration itself is barely
  detected on unseen days (held-out 01-03: 1.5 %; 2017 Thursday: 2.8 %), and 01-03 has 488 vectors that also occur
  with another label (ML-014). The infiltration class mostly teaches the model that ordinary-looking traffic is an
  attack.
- **D17: 2017 Thursday** (920 FPs): 823 are predicted "Port Scan" (median p(attack) 0.56), all on the Thursday fold.
  Every candidate, C0 included, has about 900 FPs there. Not analysed further yet; Thursday afternoon is the 2017
  infiltration session. Hypothesis only; no relabelling.

### One proposed next experiment (needs a new pre-registered version and approval; not run)

**C4-A-I: C4-A with the infiltration rows (2017 "Infiltration", 2018 "Infilteration") removed from training**
(T1 without "Lateral Movement"). Infiltration rows stay in the test folds and count as attacks, so the recall cost is
measured, not hidden. Evidence: 84 % of C4-A's D18 FPs are that class, and its own recall on unseen days is
1.5–2.8 %. Registered expectation: D18 FPs fall substantially (by at most the 1,068 above) and infiltration recall
drops to about 0. Registered caveat: **it cannot become eligible by itself**, because 2017 Thursday (about 4 %, Port
Scan predictions) is unaffected. Before any run, a model-free look at the Thursday rows (no training, no approval
needed) should establish whether that fold reflects a labelling artefact or a model error. The §7 criteria stay as
they are.

## 2017 Thursday false positives (model-free, 2026-11-02; no training)

Script: `evaluation/thursday_fp_2017.py` (reads the stored C4-A fold predictions and the 2017 CSVs); output
`experiments/dev_20261102_v2batch1/thursday_fp_C4A.json`. The MachineLearningCVE files have **no IPs or timestamps**;
`Destination Port` and row position within a file (capture order) are used for diagnosis only.

### What C4-A flags

- 920 of 21,925 Thursday benign rows: 890 in the afternoon (infiltration) file, 30 in the morning (web attacks) file.
- 823 are predicted **Port Scan** (median p(attack) 0.555, close to the 0.5 line). They are 823 distinct vectors
  but only **3 shapes**: 795 × (2 fwd, 2 bwd packets, forward initial window 1024, backward window 0), 27 × (1, 1,
  1024, 0), 1 × (1, 1, 65535, 0). Median duration 69 µs, 4 bytes forward / 12 back. They hit **568 distinct destination
  ports** (86 % ≥ 1024), and they sit between 17 % and 77 % of the file, mostly 40–75 %. Correctly classified benign
  rows go mainly to ports 53 / 443 / 80.
- The remaining 97 FPs (DDoS 45, Lateral Movement 40, others) are spread over ordinary service ports, not one shape.

### The same signature in the raw files (all rows, not the capped pool)

Signature: forward initial window 1024, ≤ 2 packets each way, no backward window.

| File | rows with signature | labels | distinct dst ports |
|---|---|---|---|
| Friday afternoon PortScan | 77,987 | **PortScan 77,984**, BENIGN 3 | 995 |
| **Thursday afternoon Infiltration** | **63,022** | **BENIGN 63,022** | 1,001 |
| each of the other 6 files | 2–21 | BENIGN | 1–7 |

On Thursday the signature rows lie mostly at 40–75 % of the file (p05–p95). The 36 rows labelled "Infiltration"
span 23–78 % of the same file.

### Assessment

- **Confirmed:** C4-A's Thursday excess comes from one repeated probe type, not from 823 independent benign
  behaviours. That probe type is labelled PortScan in 99.996 % of its Friday occurrences and BENIGN in 100 % of its
  Thursday occurrences. Its Thursday instances fall inside the infiltration period and sweep about 1,000 ports.
- **Strongly suggested but not independently verified:** these Thursday flows are port-scan traffic (consistent with
  the infiltration scenario, which by public descriptions of the dataset includes an internal Nmap scan from the
  compromised host), so the model's "Port Scan" call would be right and the label wrong. Verifying this needs the
  source/destination IPs and timestamps (the CICIDS2017 "GeneratedLabelledFlows" CSVs or the PCAPs). Those are not on
  this machine, and downloading them needs your approval. **No relabelling**; v1/v2 results stand as reported.
- **Consequence for the protocol (an observation, not a change):** under the published labels, any detector that
  recognises this port-scan signature will exceed 2 % FPR on the 2017-Thursday fold. That is why C0 (903 FPs there)
  and every candidate fail that fold. The §7 rule stays as it is. If the label error is later verified
  independently, a correction may be pre-registered as a new version. It would apply to every candidate including
  C0, both the original-label and corrected-label results would be reported, and the version would state that it
  was written after these results were seen.
- C0's Thursday predictions were not stored (batch 1 had no dump), so whether C0's 903 FPs are the same rows is
  likely but not confirmed.

### Effect on the proposed next experiment

C4-A-I (no infiltration training rows) addresses most of the 2018 FPs (84 % "Lateral Movement") but not this fold.
A passing result therefore needs both pieces: C4-A-I for the 2018 folds, and an independent check of the
2017-Thursday labels. The check needs the IP/timestamp version of the 2017 data; it is a download (approval) but not
a training run, and it comes first.

## Protocol v3 (`ML_DEV_PROTOCOL_V3.md`): runs of 2026-11-02, approved

Commands as registered in v3 §9 (both exit 0, about 10 minutes in total on an idle machine). Outputs:
`experiments/dev_20261102_v3_corrected/` (C0, C4A, C4AI on `corrected_v3`) and `experiments/dev_20261102_v3_published/`
(C4AI on published labels). Report: `evaluation/v3_report.py` writes `v3_report.json`.

Checks:
- All 44 fold manifests equal the v3 plan runs (and v1/v2 for C0/C4A).
- The correction was applied to exactly 816 pooled rows, with its hash checked.
- `models/` and `runtime/` are unchanged: classifier `6d08ef19…`, IF `46b16b74…`, golden `c8d72dd9…`, registry
  `5f76c136…`, Q-table `08209e99…`.
- The protected days are not on disk and were not read.

### Per fold: recall % / benign FPR % / benign FPs

| Fold | C0 pub | C0 corr | C4-A pub | C4-A corr | C4-A-I pub | C4-A-I corr |
|---|---|---|---|---|---|---|
| 2017 Mon | – / 0.23 / 28 | – / 0.24 / 29 | – / 0.25 / 30 | – / 0.28 / 34 | – / 0.18 / 22 | – / 0.27 / 32 |
| 2017 Tue | 3.1 / 0.38 / 45 | 2.2 / 0.37 / 44 | 1.5 / 0.85 / 101 | 0.3 / 0.71 / 85 | 0.3 / 0.29 / 35 | 0.3 / 0.36 / 43 |
| 2017 Wed | 33.4 / 0.24 / 28 | 8.1 / 0.25 / 30 | 81.8 / 0.38 / 45 | 83.7 / 0.85 / 100 | 61.0 / 0.25 / 29 | 60.6 / 0.23 / 27 |
| 2017 Thu | 17.3 / **4.12** / 903 | 39.8 / 0.41 / 87 | 7.5 / **4.20** / 920 | 32.5 / 0.52 / 110 | 29.1 / **3.99** / 874 | 47.9 / 0.36 / 75 |
| 2017 Fri | 23.4 / **2.71** / 967 | 48.7 / 0.11 / 40 | 53.7 / 0.40 / 143 | 53.9 / 0.29 / 105 | 53.8 / 0.06 / 23 | 53.6 / 0.05 / 17 |
| 2018 01-03 | 3.6 / 1.68 / 219 | 3.6 / 1.58 / 206 | 1.5 / 0.81 / 105 | 1.9 / 0.86 / 112 | 2.2 / 0.87 / 113 | 1.2 / 1.42 / 185 |
| 2018 02-03 | 0.0 / 0.13 / 19 | 0.0 / 0.12 / 17 | 94.7 / **2.64** / 376 | 93.6 / 1.82 / 259 | 62.5 / 0.15 / 21 | 62.6 / 0.15 / 21 |
| 2018 14-02 | 0.9 / 0.07 / 9 | 1.2 / 0.10 / 13 | 73.7 / 0.41 / 53 | 99.8 / 0.48 / 61 | 98.4 / 0.11 / 14 | 43.6 / 0.09 / 11 |
| 2018 15-02 | 61.7 / 0.18 / 24 | 34.1 / 0.17 / 22 | 87.3 / **5.13** / 671 | 82.8 / **4.43** / 580 | 59.0 / 0.23 / 30 | 71.4 / 0.31 / 41 |
| 2018 21-02 | 0.0 / 0.01 / 1 | 0.0 / 0.01 / 1 | 4.9 / 0.05 / 8 | 3.6 / 0.05 / 7 | 15.7 / 0.03 / 4 | 12.4 / 0.03 / 5 |
| 2018 23-02 | 0.2 / 0.15 / 21 | 0.2 / 0.12 / 16 | 56.9 / 0.41 / 56 | 63.2 / 0.66 / 90 | 27.4 / 0.11 / 15 | 33.8 / 0.11 / 15 |

Full TP/FP/TN/FN, precision, F1, PR-AUC and Brier are in the results and report JSON files.

### Macro / pooled, corrected labels (primary, v3 §5)

| | D17 recall | D17 FPR mean / pooled / worst | D18 recall | D18 FPR mean / pooled / worst |
|---|---|---|---|---|
| C0 (baseline) | 24.7 / 24.3 % | 0.28 / 0.25 / 0.41 % (Thu) | 6.5 / 14.2 % | 0.35 / 0.34 / 1.58 % (01-03) |
| C4-A | 42.6 / 44.1 % | 0.53 / 0.47 / 0.85 % (Wed) | 57.5 / 56.3 % | 1.38 / 1.36 / **4.43 %** (15-02) |
| **C4-A-I** | **40.6 / 39.6 %** | **0.25 / 0.21** / 0.36 % (Tue) | **37.5 / 43.5 %** | **0.35 / 0.34** / 1.42 % (01-03) |

Limits derived from C0 on the same labels: D17 mean FPR ≤ 0.378 %, D18 mean FPR ≤ 0.450 %, every fold ≤ 2 %.

### Pre-registered outcome

- **C4-A-I (corrected labels) is eligible and the only eligible candidate.**
  - D17 0.25 % ≤ 0.378 %; D18 0.35 % ≤ 0.450 %; worst fold 1.42 % ≤ 2 %.
  - It also meets the external-test recall rule: D18 37.5 vs C0 6.5 % (+31 points ≥ 10), and D17 40.6 % ≥ 24.7 %.
  - Under §5 it is **selected and recommended for the final external test**.
- C4-A (corrected) is not eligible: D17 mean 0.53 %, D18 mean 1.38 %, 15-02 at 4.43 %.
- Under the published labels (reported, not deciding), C4-A-I fails only the 2017-Thursday fold (3.99 %, 874 FPs, of
  which 830 are "Port Scan"), the fold the correction addresses.
- Nothing has been promoted, no threshold changed, and the external test has **not** been run (separate approval needed).

### Costs and caveats, stated before any external test

1. **Recall is unstable across small training changes.** Correcting 816 rows (0.3 % of the pool) moved single-fold
   recall by up to 55 points: C4-A-I 14-02 98.4 → 43.6 %, C0 Wednesday 33.4 → 8.1 %, C0 Friday 23.4 → 48.7 %.
   C4-A-I's D18 macro recall is 44.2 % on published and 37.5 % on corrected labels. FPR moved far less. Fold recall
   is therefore a noisy estimate. The +31-point margin over C0 is large, but recall figures must not be quoted to
   one decimal as if stable.
2. **C4-A-I trades detection for fewer false alarms.** Its 2018 per-family flagged rate is below C4-A's: botnet
   62.6 vs 93.6 %, brute force 42.6 vs 96.7 %, web 44.8 vs 85.6 %, DoS/DDoS 51.0 vs 55.5 %. Infiltration was already
   ~2 %; it stays at 1.2–2.8 %, flagged as other classes. Removing infiltration from training changed more than the
   "Lateral Movement" class. C4-A-I has no infiltration class.
3. **The deployment FPR criterion is far away.** The deployment rule needs a benign-FPR Wilson upper bound
   ≤ 0.10 % on the protected days, at an operating line chosen on D17/D18 only. At the argmax decision C4-A-I runs
   at 0.21–0.34 % pooled. A stricter line must be **pre-registered from the D17/D18 prediction dumps before** the
   external test; recall will drop with it.
4. **Latency on this idle run is comparable to batch 3:** 5.2–7.3 µs/row in batch, models 3.4–3.7 MB (C0 3.2–3.6 MB).
   Single-flow p95 (≤ 50 ms) has not been measured yet.
5. **Taxonomy:** C4-A-I uses T1 two-stage classes, not the served T0. Deployment would need an approved class
   migration; the external test does not.
6. The correction relies on a mirror file whose IP and timestamp columns could not be authenticated beyond the
   100 % row join.

### Recommended order before the one-shot external test (each needs approval; none started)

1. **Operating line (no training):** pre-register a decision threshold on C4-A-I's corrected-label D17/D18
   `p_attack` dumps. For example, the highest-recall line whose pooled dev FPR Wilson upper bound is ≤ 0.10 %;
   report the recall it costs.
2. **Seed stability (training):** C4-A-I and C0 on corrected labels with 2 more seeds, to bound the recall variance
   seen above before the single external run.
3. **External test:** download the four protected days (4.98 GB), then one run of C4-A-I and C0 with the frozen
   line, published 2018 labels, and the latency measurement.

## v3 stability check (`ML_DEV_PROTOCOL_V3.md` §10; run 2026-11-02, approved)

**Why the training data and not the XGBoost seed.** The XGBoost seed is inert in this configuration: identical
predictions for seeds 42, 1 and 2. The check therefore retrains C0 and C4-A-I (corrected labels, D17 + D18) on a seeded
random 90 % of each fold's training rows.
- Replicates: seeds 1 and 2. Both candidates see the same subsample of each fold.
- Checks: both exit 0; test rows identical to v3; training exactly 90 %; correction applied (816 rows); `models/` and
  `runtime/` unchanged; protected days not read.
- Report: `evaluation/stability_report.py` writes `experiments/dev_20261102_v3_corrected/stability_report.json`.

### Argmax decision (as used by §5 eligibility)

| | full | 90 % seed 1 | 90 % seed 2 |
|---|---|---|---|
| C4-A-I D17 recall / FPR | 40.6 / 0.25 % | 42.0 / 0.26 % | 52.4 / 0.25 % |
| C4-A-I D18 recall / FPR | 37.5 / 0.35 % | 47.4 / 0.38 % | 44.1 / 0.39 % |
| C4-A-I worst fold FPR | 1.42 % | 1.39 % | 1.42 % |
| C0 D17 recall / FPR | 24.7 / 0.28 % | 25.2 / 0.50 % | 31.5 / 0.67 % (Fri 2.10 %) |
| C0 D18 recall / FPR | 6.5 / 0.35 % | 7.5 / 0.33 % | 6.6 / 0.33 % |
| **C4-A-I eligible (§5)?** | yes | **yes** | **yes** |

C4-A-I also stays within the full-run limits (D17 ≤ 0.378 %, D18 ≤ 0.450 %) in both replicates, so its eligibility
does not depend on C0 getting worse. **FPR is stable** (D18 0.35–0.39 %). **Recall is not:**
- C4-A-I D18 macro recall ranges 37.5–47.4 %.
- Single folds swing widely: 14-02 43.6–98.9 %, 2017 Thursday 47.9–93.6 %, C0 Wednesday 8.1–34.8 %.
- The argmax recall lead over C0 stays above 30 points in every replicate.

### Frozen operating lines (C4-A-I 0.915614, C0 0.974834)

| | full | 90 % seed 1 | 90 % seed 2 |
|---|---|---|---|
| C4-A-I pooled FPR / Wilson UB | 0.085 / 0.0997 % | 0.082 / 0.0966 % | 0.084 / 0.0991 % |
| C0 pooled FPR / Wilson UB | 0.085 / 0.0997 % | 0.071 / 0.0842 % | 0.080 / 0.0947 % |
| Line §2 would choose: C4-A-I / C0 | 0.9156 / 0.9748 | 0.9094 / 0.9699 | 0.9164 / 0.9688 |
| **2018 folds pooled recall: C4-A-I / C0** | 14.2 / 13.3 % (+0.9) | 13.4 / 9.0 % (+4.4) | 20.4 / 13.1 % (+7.3) |
| 2018 DoS/DDoS at line: C4-A-I / C0 | 21.9 / 21.5 % | 20.9 / 14.5 % | 27.3 / 21.3 % |
| 2018 macro recall: C4-A-I / C0 | 7.5 / 5.8 % | 7.3 / 4.0 % | 13.2 / 5.8 % |

- **The lines are stable.** The line §2 would choose moves by at most 0.007, and at the frozen lines the FPR bound
  stays ≤ 0.10 % in every replicate. The frozen lines stay as they are.
- **At those lines the advantage on 2018 traffic is +0.9 to +7.3 points.** That is below the +10 points the deployment
  criterion requires, in every replicate. The protected days are 2018 days dominated by DoS/DDoS (20-02, LOIC-HTTP, is
  most of the volume), and C4-A-I is no better than C0 on 2018 DoS/DDoS at these lines in the full run
  (21.9 vs 21.5 %).

### Conclusion

1. C4-A-I's selection under §5 is **robust**: eligible in all three models, with a stable FPR.
2. The frozen lines are **robust**.
3. The development evidence consistently predicts that the **deployment criterion would fail** on the protected 2018
   days. This is now shown on three models, not one.

The rules are not changed. The one-shot external test can still be run as registered; on this evidence it would most
likely confirm "do not deploy" and would use up the protected days. The served model stays either way.

## Protocol v4

Domain-balanced candidates (`ML_DEV_PROTOCOL_V4.md`), run 2026-11-13. The protocol and script were committed
before the run (06b8d8a). Results: `ai-engine/experiments/candidate_v4_20261113/results.json`.

- **Inputs:** corrected_v3 labels, frozen v3 folds, the six 2018 development days only (protected days not opened).
- **Reproduction:** C0 and C4AI reproduce their v3 fold results exactly (22 of 22 folds).
- **Decision:** binary decision at the classifier, as in v1–v3.

| Candidate | D17 macro recall | D17 pooled FPR | D18 macro recall | D18 pooled FPR | Worst-fold FPR (D17 / D18) | Mean balanced acc. (D17 / D18) |
|---|---|---|---|---|---|---|
| C0 (served recipe) | 24.7 % | 0.25 % | 6.5 % | 0.34 % | 0.41 / 1.58 % | 0.622 / 0.531 |
| C4AI (v3 reference) | 40.6 % | 0.21 % | 37.5 % | 0.34 % | 0.36 / 1.42 % | 0.702 / 0.686 |
| C5 (domain-balanced, regularised) | 33.5 % | 0.53 % | 40.5 % | 0.57 % | 0.82 / **2.35 %** | 0.665 / 0.699 |
| C5E (C5 + feature set E) | 39.8 % | **1.40 %** | 32.5 % | **2.28 %** | **3.03 / 3.67 %** | 0.691 / 0.651 |

Paired fold differences (mean, 95 % bootstrap CI over folds):

| Comparison | Recall difference | FPR difference |
|---|---|---|
| C5 − C0, D18 | **+34.0 pp** (+7.4 to +64.2) | +0.24 pp (+0.04 to +0.50) |
| C5 − C0, D17 | +7.1 pp (−16.0 to +27.4) | +0.30 pp (+0.21 to +0.45) |
| C5 − C4AI, D17 | −5.7 pp (−25.2 to +12.1) | +0.33 pp |
| C5 − C4AI, D18 | +3.0 pp (−14.9 to +26.0) | +0.24 pp |

**Pre-registered outcome: no candidate is eligible.**
- **C5** fails four conditions:
  - D17 recall is below C4AI.
  - Pooled FPR exceeds C4AI's by more than 0.10 pp on both fold sets.
  - The D18 worst fold reaches 2.35 % FPR.
- **C5E** fails all six.

Domain balancing raises recall on unseen 2018 days over the served recipe, but buys it with more false alarms and
does not beat the v3 reference. Nothing was saved to `models/`, registered or promoted; `xgb_cicids_v1` is
unchanged.
