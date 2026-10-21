| Protocol | Accuracy | Macro F1 | Weighted F1 | Benign FPR (threat raised) | Attack detection (threat raised) |
|---|---|---|---|---|---|
| Random 80/20 (as reported) | 0.9926 | 0.8757 | 0.9932 | 0.1875% [0.1457%, 0.2413%] | 0.9531 |
| Chronological per class | 0.9891 | 0.7718 | 0.9898 | 0.1588% [0.1404%, 0.1795%] | 0.9113 |
| Leave-out Monday | 0.9972 | 0.9986 | 0.9986 | 0.0600% [0.0343%, 0.1049%] | - |
| Leave-out Tuesday | 0.6847 | 0.2723 | 0.5606 | 0.0500% [0.0272%, 0.0920%] | 0.0021 |
| Leave-out Wednesday | 0.6654 | 0.2740 | 0.5475 | 0.0500% [0.0272%, 0.0920%] | 0.0690 |
| Leave-out Thursday | 0.9342 | 0.1975 | 0.9366 | 1.4075% [1.2966%, 1.5277%] | 0.8017 |
| Leave-out Friday | 0.8398 | 0.3084 | 0.8152 | 0.0400% [0.0269%, 0.0595%] | 0.1027 |

Score rule comparison (same models): attack detection / benign FPR

| Protocol | Threat raised: legacy blend | Threat raised: current | Block line: legacy blend | Block line: current |
|---|---|---|---|---|
| Random 80/20 | 0.09% / 0.0000% | 95.31% / 0.1875% | 0.00% / 0.0000% | 94.86% / 0.1781% |
| Chronological per class | 0.00% / 0.0000% | 91.13% / 0.1587% | 0.00% / 0.0000% | 90.56% / 0.1444% |
| Leave-out Monday | - / 0.0000% | - / 0.0600% | - / 0.0000% | - / 0.0500% |
| Leave-out Tuesday | 0.00% / 0.0000% | 0.21% / 0.0500% | 0.00% / 0.0000% | 0.19% / 0.0400% |
| Leave-out Wednesday | 0.00% / 0.0000% | 6.90% / 0.0500% | 0.00% / 0.0000% | 6.72% / 0.0400% |
| Leave-out Thursday | 0.00% / 0.0000% | 80.17% / 1.4075% | 0.00% / 0.0000% | 80.13% / 1.4075% |
| Leave-out Friday | 0.00% / 0.0000% | 10.27% / 0.0400% | 0.00% / 0.0000% | 8.80% / 0.0317% |
