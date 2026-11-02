# Operating line for the external test (protocol v3), pre-registered 2026-11-02

This rule was written **before** any threshold curve was computed from the v3 prediction dumps. It implements
v1 §7's deployment requirement, "benign FPR Wilson upper bound ≤ 0.10 % at a line chosen on D17/D18 only", for the
selected candidate C4-A-I and the baseline C0. It uses no protected data, involves no training, and changes no
production threshold.

## 1. Inputs (frozen)

- `experiments/dev_20261102_v3_corrected/predictions_C4AI.csv` and `predictions_C0.csv`: out-of-fold predictions
  for every development test row of the 11 folds (D17 ∪ D18, disjoint test sets), on the `corrected_v3` labels
  (column `label_used`). The line script records their sha256.
- Score: `p_attack`. This is stage-1 P(attack) for C4-A-I and 1 − P(BENIGN) for C0. A row is an alarm when
  `p_attack ≥ t`. At t = 0.5 this equals C4-A-I's argmax decision. For C0 it can differ slightly from argmax, so C0
  is evaluated on the same `p_attack ≥ t` basis throughout.

## 2. Rule

1. Candidate thresholds are every distinct `p_attack` value in [0.5, 1], plus 0.5 itself.
2. For each t, pool all benign test rows of the 11 folds; each row appears once, because folds are disjoint. Compute
   FP(t), the benign FPR and its Wilson 95 % upper bound.
3. **The line is the smallest t whose Wilson upper bound is ≤ 0.10 %.** That gives the highest recall that meets the
   constraint. If no t qualifies, there is **no line**, and the deployment criterion is recorded as unattainable for
   that model.
4. Reported for the chosen t, for information only (not used to choose):
   - pooled and per-fold recall and FPR;
   - per-family flagged rate;
   - recall lost against the argmax decision.
5. The same rule is applied to C0, so that C0 is compared at its own line in the external test.

## 3. Assumptions, stated

- The final model for the external test is trained on all development data. Its scores are assumed to be
  distributed like the out-of-fold scores here. Different training data shifts scores, so the line may not transfer
  exactly, which is why the external test measures FPR again rather than assuming it.
- The line comes from one seed. The seed-stability step (if approved) reports how much the line would move, and it
  does **not** re-choose it: the line frozen here is the one used.

## 4. Result

(Filled in after the computation, below this line. Section 2 is not edited.)

Computed 2026-11-02 with `ai-engine/evaluation/operating_line.py` (output
`experiments/dev_20261102_v3_corrected/operating_line.json`; test in `tests/test_dev_protocol_v2.py`). 174,358
benign development test rows pooled over the 11 folds.

### Frozen lines

| Model | Prediction dump sha256 | **Line t (p_attack ≥ t)** | Benign FPs | Pooled FPR | Wilson 95 % UB |
|---|---|---|---|---|---|
| C4-A-I | `7a6fce16c3a0…` | **0.915614** | 148 | 0.0849 % | 0.0997 % |
| C0 | `7347ffd10eed…` | **0.974834** | 148 | 0.0849 % | 0.0997 % |

Both lines land on 148 FPs because the bound is a function of FP count and n only.

### What the line costs (development folds, corrected labels; information, not a selection criterion)

| | C4-A-I at 0.5 | **C4-A-I at line** | C0 at 0.5 | **C0 at line** |
|---|---|---|---|---|
| Pooled recall | 41.9 % | **19.1 %** | 19.0 % | **9.4 %** |
| D17 macro recall | 40.6 % | 24.2 % | 26.5 % | 7.6 % |
| D18 macro recall | 37.5 % | **7.5 %** | 6.5 % | **5.8 %** |
| D17 / D18 macro FPR | 0.25 / 0.35 % | 0.07 / 0.11 % | 0.30 / 0.35 % | 0.07 / 0.11 % |
| Worst fold FPR | 1.42 % (01-03) | 0.49 % (01-03) | 1.59 % (01-03) | 0.55 % (01-03) |

C4-A-I per family at the line: Reconnaissance 53 %, DoS/DDoS 30 %, botnet 5.3 %, web 3.1 %, brute force 0.7 %,
infiltration 0.3 %.

### Prognosis for the external test (stated before it is run; the rules are unchanged)

The deployment criterion requires, on the protected 2018 days at the frozen lines, binary recall at least 10 points
above C0's **and** a benign-FPR Wilson upper bound of at most 0.10 %. On the development folds:
- the 2018-fold advantage of C4-A-I over C0 at these lines is **+1.7 points macro**;
- pooled over all folds it is **+9.7 points**, and most of that comes from 2017 port scans.

C4-A-I's cross-day 2018 recall almost vanishes once false alarms are held at 0.1 %. So the development data predict
that the deployment criterion will **most likely not be met**. The external test can still be run (v3 §5 recommends
it on the argmax rule), but it is a single, irreversible use of the protected days. That decision is yours. Running
the seed-stability check first would also show whether these lines are stable.

### Stability (2026-11-02, after freezing; see ML_DEV_RESULTS.md, v3 stability check)

Across the full-data model and two 90 %-training-subsample replicates, the line §2 would choose moves by at most 0.007
(C4-A-I 0.909–0.916, C0 0.969–0.975), and the FPR bound at the frozen lines stays ≤ 0.10 %. The frozen lines are kept.
The 2018-fold recall advantage of C4-A-I over C0 at the lines is +0.9 / +4.4 / +7.3 points: below +10 in every replicate.
