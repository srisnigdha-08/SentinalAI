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
