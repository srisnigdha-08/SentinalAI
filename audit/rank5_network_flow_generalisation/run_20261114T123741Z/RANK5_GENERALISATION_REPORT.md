# Rank 5: generalisation evidence for the frozen network-flow model (xgb_cicids_v1)

Generated 2026-11-14T12:50:01.513588+00:00 by `ai-engine/evaluation/rank5_generalisation.py` (rank5/1, seed 20261114, 740.4 s).

## Status

| Item | Status |
|---|---|
| evaluation_tooling | READY |
| model_integrity | READY |
| dataset_provenance | READY |
| random_split_reproduced | READY |
| chronological_evaluation | LIMITED |
| leakage_checks | LIMITED |
| drift_diagnostics | READY |
| independent_generalisation | NOT_VERIFIED |
| generalisation_finding | POOR_ON_LATER_DIFFERENT_NETWORK |

## Model identity and integrity

- Model `xgb_cicids_v1`; artifacts unchanged before/after the run: **True**.
- classifier: `xgb_classifier_xgb_cicids_v1.pkl` sha256 `6d08ef19dad31bf6423eb91cb42105f786800307f5690efd2c94db6a8736360b` (registry match)
- anomaly: `isolation_forest_xgb_cicids_v1.pkl` sha256 `46b16b745613f1ccec6afb04d89c0732c504c19aa2e308af382922179e5ec053` (registry match)
- golden: `golden_set.json` sha256 `c8d72dd96dc35287e7dd15c1af1e9c4c3b6a4a2f79507e04cc34359bd0420af6` (registry match)
- Feature contract v2.1_53feat, 53 features; operating lines alert 0.9, block 0.92.
- Production request path parity: 2100 sampled rows scored through `SentinelPredictor.predict(record)`, 0 mismatches.
- Training provenance (model meta): {"git_commit": "cf667f13d603ebfdd7b1acd45584f0b57c454f8f", "git_dirty": true, "sklearn": "1.4.0", "numpy": "1.26.4", "python": "3.11.9"}; meta evaluation: {"split": "stratified_random_80_20", "random_state": 42, "deduplicated": true, "independent_holdout": false, "note": "Random row split; see evaluation/day_holdout_eval.py for chronological and leave-one-day-out results"}.

## Dataset provenance

| File | Day | sha256 matches training record |
|---|---|---|
| Monday-WorkingHours.pcap_ISCX.csv | 2017-07-03 | True |
| Tuesday-WorkingHours.pcap_ISCX.csv | 2017-07-04 | True |
| Wednesday-workingHours.pcap_ISCX.csv | 2017-07-05 | True |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 2017-07-06 | True |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 2017-07-06 | True |
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 2017-07-07 | True |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 2017-07-07 | True |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 2017-07-07 | True |

| 2018 file | Day | CSV rows | Evaluated | Unique (vector,label) | Vector in 2017 pool | Timestamp range | Labels |
|---|---|---|---|---|---|---|---|
| Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv | 2018-02-14 | 1,048,575 | 1,044,751 | 619,346 | 1,188 | 1970-01-05T03:01:17 .. 2018-02-14T12:59:59 | benign, ftp bruteforce, ssh bruteforce |
| Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv | 2018-02-15 | 1,048,575 | 1,040,548 | 794,812 | 2,817 | 2018-02-15T01:00:00 .. 2018-02-15T12:59:59 | benign, dos attacks goldeneye, dos attacks slowloris |
| Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv | 2018-02-21 | 1,048,575 | 1,048,575 | 561,388 | 0 | 2018-02-21T01:55:46 .. 2018-02-21T10:43:21 | benign, ddos attack hoic, ddos attack loic udp |
| Friday-23-02-2018_TrafficForML_CICFlowMeter.csv | 2018-02-23 | 1,048,575 | 1,042,867 | 829,409 | 1,815 | 2018-02-23T01:00:00 .. 2018-02-23T12:59:59 | benign, brute force web, brute force xss, sql injection |
| Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv | 2018-03-01 | 331,100 | 328,181 | 249,150 | 2,074 | 2018-03-01T01:00:00 .. 2018-03-01T12:59:59 | benign, infilteration |
| Friday-02-03-2018_TrafficForML_CICFlowMeter.csv | 2018-03-02 | 1,048,575 | 1,044,525 | 771,587 | 4,799 | 2018-03-02T01:00:00 .. 2018-03-02T12:59:59 | benign, bot |

## Leakage and split checks

- **E1 test vectors also in E1 train**: {"count": 15, "of": 24907} (drop_duplicate_rows removes identical (vector, label) rows only; a vector with conflicting labels can sit on both sides)
- **E1 split is random over rows of the same days and attack episodes**: {"result": "IN-DISTRIBUTION"} (not chronological; inflates generalisation estimates by construction)
- **E2 rows sharing a vector with the training pool**: {"result": "excluded before scoring", "count": 390049}
- **E2 rows from the same capture days and attack episodes as training**: {"result": "LEAKY BY DESIGN"} (E2 measures unseen rows, not unseen traffic)
- **E3 rows sharing an exact vector with the 2017 training pool**: {"count": 12693, "of": 5549447}
- **E3 chronologically after every training row**: {"result": "PASS", "rows_dated_on_or_before_training": 0, "rows_with_implausible_dates": 5} (2017 training days 2017-07-03..2017-07-07 (published schedule; file names). Rows dated before 2000-01-01 are clock artefacts in the source CSV and are reported separately)
- **2018 files cut at the spreadsheet row limit**: {"result": "SUSPECTED", "files": {"Friday-02-03-2018_TrafficForML_CICFlowMeter.csv": 1048575, "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv": 1048575, "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv": 1048575, "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv": 1048575, "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv": 1048575}} (exactly 1,048,575 data rows suggests the published CSV was saved by a spreadsheet program and later flows of that day are missing; metrics cover only the rows present)
- **protected 2018 days opened**: {"result": "NO"} (assert_permitted on every path; none on disk)
- **preprocessing fitted on test data**: {"result": "NO"} (the served StandardScaler / models were fitted once at training; nothing is fitted here)
- **time-of-day features**: {"result": "constant 0 in training and in every set here (no timestamp passed)"}
- **E3 used in earlier development**: {"result": "YES"} (the six days trained / selected OTHER candidates (protocols v2-v4); never this model or its lines)
- **near-duplicate flows**: {"result": "NOT_CHECKED"} (only exact duplicates are measured)

Leakage assessment: **LIMITED**.

## Overall metrics (argmax class; binary = attack vs benign)

| Set | n | Accuracy | Balanced acc. | Macro P | Macro R | Macro F1 | Weighted F1 | FPR | FNR | ROC-AUC | PR-AUC | Recall @ alert line | FPR @ alert line |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| E1 random split (not independent) | 24,907 | 0.9897 | 0.8848 | 0.8944 | 0.8848 | 0.8738 | 0.9907 | 0.0036 | 0.0019 | 0.9998 | 0.9995 | 0.9522 | 0.0023 |
| E2 2017 unseen rows (same days) | 2,289,812 | 0.9980 | 0.9826 | 0.9748 | 0.9826 | 0.9787 | 0.9985 | 0.0021 | 0.0011 | 0.9999 | 0.9997 | 0.9958 | 0.0010 |
| E2 de-duplicated | 2,108,464 | 0.9979 | 0.9789 | 0.9704 | 0.9789 | 0.9746 | 0.9985 | 0.0021 | 0.0011 | 0.9999 | 0.9997 | n/a | n/a |
| E3 2018 development days | 5,549,447 | 0.7294 | 0.1273 | 0.2343 | 0.1273 | 0.1145 | 0.6416 | 0.0045 | 0.7819 | 0.6546 | 0.5044 | 0.1498 | 0.0039 |
| E3 de-duplicated | 3,672,442 | 0.8525 | 0.1334 | 0.2445 | 0.1334 | 0.1309 | 0.7900 | 0.0016 | 0.9680 | 0.6045 | 0.2531 | n/a | n/a |
| E3 without vectors seen in 2017 | 5,536,754 | 0.7289 | 0.1273 | 0.2342 | 0.1273 | 0.1145 | 0.6410 | 0.0046 | 0.7818 | 0.6551 | 0.5051 | n/a | n/a |

| Majority baseline | Predicts | Accuracy | Balanced acc. | Macro F1 |
|---|---|---|---|---|
| E1 | BENIGN | 0.7496 | 0.1000 | 0.0857 |
| E2 | BENIGN | 0.8647 | 0.3333 | 0.3091 |
| E3 | BENIGN | 0.7296 | 0.1250 | 0.1055 |

## Per-class metrics

| Set | Class | Training rows | Support | Predicted | Precision | Recall | F1 | Reliable (support >= 30) |
|---|---|---|---|---|---|---|---|---|
| E1 | BENIGN | 74,682 | 18,671 | 18,616 | 0.9994 | 0.9964 | 0.9979 | True |
| E1 | SSH Brute Force | 2,575 | 644 | 645 | 0.9984 | 1.0000 | 0.9992 | True |
| E1 | SQL Injection | 17 | 4 | 2 | 1.0000 | 0.5000 | 0.6667 | False |
| E1 | Port Scan | 283 | 71 | 80 | 0.8500 | 0.9577 | 0.9007 | True |
| E1 | DDoS | 14,440 | 3,610 | 3,620 | 0.9967 | 0.9994 | 0.9981 | True |
| E1 | RCE Attempt | 9 | 2 | 2 | 1.0000 | 1.0000 | 1.0000 | False |
| E1 | XSS Attempt | 522 | 130 | 253 | 0.4071 | 0.7923 | 0.5379 | True |
| E1 | Malware Beacon | 1,149 | 288 | 323 | 0.8824 | 0.9896 | 0.9329 | True |
| E1 | Credential Stuffing | 5,921 | 1,480 | 1,360 | 0.9772 | 0.8980 | 0.9359 | True |
| E1 | Lateral Movement | 29 | 7 | 6 | 0.8333 | 0.7143 | 0.7692 | False |
| E2 | BENIGN | 74,682 | 1,980,024 | 1,976,217 | 0.9998 | 0.9979 | 0.9989 | True |
| E2 | SSH Brute Force | 2,575 | 0 | 37 | 0.0000 | n/a | n/a | False |
| E2 | SQL Injection | 17 | 0 | 65 | 0.0000 | n/a | n/a | False |
| E2 | Port Scan | 283 | 1,971 | 2,016 | 0.9301 | 0.9513 | 0.9406 | True |
| E2 | DDoS | 14,440 | 307,817 | 309,092 | 0.9945 | 0.9987 | 0.9966 | True |
| E2 | RCE Attempt | 9 | 0 | 1 | 0.0000 | n/a | n/a | False |
| E2 | XSS Attempt | 522 | 0 | 85 | 0.0000 | n/a | n/a | False |
| E2 | Malware Beacon | 1,149 | 0 | 1,969 | 0.0000 | n/a | n/a | False |
| E2 | Credential Stuffing | 5,921 | 0 | 285 | 0.0000 | n/a | n/a | False |
| E2 | Lateral Movement | 29 | 0 | 45 | 0.0000 | n/a | n/a | False |
| E3 | BENIGN | 74,682 | 4,049,104 | 5,203,868 | 0.7746 | 0.9955 | 0.8712 | True |
| E3 | SSH Brute Force | 2,575 | 187,589 | 556 | 0.0000 | 0.0000 | 0.0000 | True |
| E3 | SQL Injection | 17 | 53 | 19 | 0.0000 | 0.0000 | 0.0000 | True |
| E3 | Port Scan | 283 | 0 | 231,459 | 0.0000 | n/a | n/a | False |
| E3 | DDoS | 14,440 | 740,240 | 18,832 | 0.8963 | 0.0228 | 0.0445 | True |
| E3 | RCE Attempt | 9 | 0 | 1 | 0.0000 | n/a | n/a | False |
| E3 | XSS Attempt | 522 | 151 | 365 | 0.0000 | 0.0000 | 0.0000 | True |
| E3 | Malware Beacon | 1,149 | 286,191 | 557 | 0.0467 | 0.0001 | 0.0002 | True |
| E3 | Credential Stuffing | 5,921 | 193,716 | 93,675 | 0.0000 | 0.0000 | 0.0000 | True |
| E3 | Lateral Movement | 29 | 92,403 | 115 | 0.1565 | 0.0002 | 0.0004 | True |

Classes with no training rows: Data Exfiltration. The model cannot have learned them; no detection of them is claimed.

## Per-day metrics

| Set | Day | n | Benign | Attack | Accuracy | Balanced acc. | Macro F1 | FPR | FNR | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|---|
| E1_random_split | 2017-07-03 | 2,414 | 2414 | 0 | 0.9979 | 0.9979 | 0.9990 | 0.0021 | n/a | n/a |
| E1_random_split | 2017-07-04 | 4,180 | 2343 | 1837 | 0.9995 | 0.9997 | 0.9997 | 0.0009 | 0.0000 | 1.0000 |
| E1_random_split | 2017-07-05 | 3,979 | 2379 | 1600 | 0.9967 | 0.9980 | 0.9987 | 0.0046 | 0.0006 | 1.0000 |
| E1_random_split | 2017-07-06 | 4,857 | 4429 | 428 | 0.9580 | 0.6951 | 0.7279 | 0.0050 | 0.0140 | 0.9989 |
| E1_random_split | 2017-07-07 | 9,477 | 7106 | 2371 | 0.9965 | 0.9859 | 0.9829 | 0.0038 | 0.0021 | 0.9998 |
| E2_2017_unseen_rows | 2017-07-03 | 488,166 | 488166 | 0 | 0.9981 | 0.9981 | 0.9991 | 0.0019 | n/a | n/a |
| E2_2017_unseen_rows | 2017-07-04 | 391,882 | 391882 | 0 | 0.9990 | 0.9990 | 0.9995 | 0.0010 | n/a | n/a |
| E2_2017_unseen_rows | 2017-07-05 | 584,347 | 394552 | 189795 | 0.9980 | 0.9980 | 0.9983 | 0.0019 | 0.0014 | 1.0000 |
| E2_2017_unseen_rows | 2017-07-06 | 354,312 | 354312 | 0 | 0.9975 | 0.9975 | 0.9988 | 0.0025 | n/a | n/a |
| E2_2017_unseen_rows | 2017-07-07 | 471,105 | 351112 | 119993 | 0.9972 | 0.9826 | 0.9906 | 0.0034 | 0.0007 | 1.0000 |
| E3_2018_development_days | 2018-02-14 | 1,044,751 | 663808 | 380943 | 0.6346 | 0.3329 | 0.3111 | 0.0013 | 0.2469 | 0.9852 |
| E3_2018_development_days | 2018-02-15 | 1,040,548 | 988050 | 52498 | 0.9644 | 0.6600 | 0.7320 | 0.0015 | 0.6776 | 0.8401 |
| E3_2018_development_days | 2018-02-21 | 1,048,575 | 360833 | 687742 | 0.3440 | 0.4999 | 0.2560 | 0.0002 | 1.0000 | 0.1923 |
| E3_2018_development_days | 2018-02-23 | 1,042,867 | 1042301 | 566 | 0.9984 | 0.2504 | 0.2510 | 0.0011 | 0.9965 | 0.7757 |
| E3_2018_development_days | 2018-03-01 | 328,181 | 235778 | 92403 | 0.6749 | 0.4697 | 0.4210 | 0.0607 | 0.7474 | 0.6004 |
| E3_2018_development_days | 2018-03-02 | 1,044,525 | 758334 | 286191 | 0.7255 | 0.4997 | 0.4206 | 0.0007 | 0.9999 | 0.7155 |
| E3_2018_alert_line | 2018-02-14 | 1,044,751 | 663808 | 380943 | 0.6346 | 0.3329 | 0.3111 | 0.0007 | 0.4924 | 0.9852 |
| E3_2018_alert_line | 2018-02-15 | 1,040,548 | 988050 | 52498 | 0.9644 | 0.6600 | 0.7320 | 0.0007 | 0.8466 | 0.8401 |
| E3_2018_alert_line | 2018-02-21 | 1,048,575 | 360833 | 687742 | 0.3440 | 0.4999 | 0.2560 | 0.0002 | 1.0000 | 0.1923 |
| E3_2018_alert_line | 2018-02-23 | 1,042,867 | 1042301 | 566 | 0.9984 | 0.2504 | 0.2510 | 0.0006 | 0.9982 | 0.7757 |
| E3_2018_alert_line | 2018-03-01 | 328,181 | 235778 | 92403 | 0.6749 | 0.4697 | 0.4210 | 0.0581 | 0.7486 | 0.6004 |
| E3_2018_alert_line | 2018-03-02 | 1,044,525 | 758334 | 286191 | 0.7255 | 0.4997 | 0.4206 | 0.0002 | 0.9999 | 0.7155 |

## Drift diagnostics (training rows vs each 2018 day)

Method: {"psi": "10 bins at reference quantiles; bands: <0.10 small, 0.10-0.25 moderate, >=0.25 large (convention)", "ks": "two-sample Kolmogorov-Smirnov statistic (p-values are ~0 at these sample sizes and not reported)", "sample": "up to 20000 rows per day, deterministic (seed 20261114)"}.

| Day | Features PSI large / moderate / small (all rows) | Median KS (all) | Benign: PSI large | Median KS (benign) | Top PSI features | Alert rate | Mean P(attack) |
|---|---|---|---|---|---|---|---|
| 2018-02-14 | 33 / 2 / 12 | 0.24905 | 28 | 0.13385 | bwd_packet_len_max, bwd_packet_len_mean, bwd_iat_min, fwd_header_len | 0.185533 | 0.265384 |
| 2018-02-15 | 27 / 7 / 13 | 0.1271 | 27 | 0.12935 | fwd_header_len, bwd_packet_len_max, bwd_iat_min, bwd_packet_len_mean | 0.008412 | 0.033952 |
| 2018-02-21 | 37 / 0 / 10 | 0.3386 | 38 | 0.596728 | bwd_packet_len_max, fwd_iat_total, fwd_iat_max, bwd_packet_len_mean | 7.9e-05 | 0.000573 |
| 2018-02-23 | 30 / 4 / 13 | 0.1407 | 29 | 0.15715 | fwd_header_len, bwd_iat_min, bwd_packet_len_max, bwd_header_len | 0.000552 | 0.014908 |
| 2018-03-01 | 31 / 4 / 12 | 0.1548 | 28 | 0.132155 | fwd_header_len, bwd_iat_min, bwd_packet_len_max, bwd_header_len | 0.112539 | 0.12137 |
| 2018-03-02 | 32 / 4 / 11 | 0.1659 | 30 | 0.16075 | bwd_packet_len_max, bwd_iat_min, fwd_header_len, bwd_packet_len_std | 0.000138 | 0.010987 |

Feature shift is not proof of concept drift: the 2018 days come from another network, another attack toolset and another CICFlowMeter build, so covariate, measurement and label-definition differences cannot be separated with this data.

## Limitations

- E1 and E2 share capture days and attack episodes with the training data: they measure in-distribution performance only.
- E3 is later and from a different network, but its six days were used in earlier development (other candidates), its labels are the dataset's own (known noisy, e.g. infiltration labelled by time window) and mapped to the served classes by evaluation/taxonomies.py.
- Several 2018 files appear cut at the spreadsheet row limit (see checks); later flows of those days are missing.
- Only exact duplicates are measured; near-duplicates are not.
- The four protected 2018 days were not used; they remain the registered one-shot external test (owner approval).
