| Protocol | Accuracy | Macro F1 | Weighted F1 | Benign FPR (threat raised) | Attack detection (threat raised) |
|---|---|---|---|---|---|
| Chronological per class | 0.9307 | 0.6194 | 0.9507 | 1.7619% [1.6986%, 1.8275%] | 0.7875 |
| Leave-out Monday | 0.9451 | 0.9718 | 0.9718 | 0.9900% [0.8619%, 1.1369%] | - |
| Leave-out Tuesday | 0.6658 | 0.2678 | 0.5505 | 0.0200% [0.0078%, 0.0514%] | 0.0000 |
| Leave-out Wednesday | 0.6384 | 0.2604 | 0.5205 | 0.4050% [0.3260%, 0.5031%] | 0.0033 |
| Leave-out Thursday | 0.9000 | 0.1899 | 0.9006 | 0.4050% [0.3473%, 0.4722%] | 0.0009 |
| Leave-out Friday | 0.8341 | 0.3139 | 0.7891 | 0.0200% [0.0114%, 0.0350%] | 0.0040 |

Score rule comparison (same models): attack detection / benign FPR

| Protocol | Threat raised: legacy blend | Threat raised: current | Block line: legacy blend | Block line: current |
|---|---|---|---|---|
| Chronological per class | 0.00% / 0.0000% | 78.75% / 1.7619% | 0.00% / 0.0000% | 78.41% / 1.3137% |
| Leave-out Monday | - / 0.0000% | - / 0.9900% | - / 0.0000% | - / 0.1950% |
| Leave-out Tuesday | 0.00% / 0.0000% | 0.00% / 0.0200% | 0.00% / 0.0000% | 0.00% / 0.0200% |
| Leave-out Wednesday | 0.00% / 0.0000% | 0.33% / 0.4050% | 0.00% / 0.0000% | 0.27% / 0.1150% |
| Leave-out Thursday | 0.00% / 0.0000% | 0.09% / 0.4050% | 0.00% / 0.0000% | 0.00% / 0.1175% |
| Leave-out Friday | 0.00% / 0.0000% | 0.40% / 0.0200% | 0.00% / 0.0000% | 0.39% / 0.0133% |
