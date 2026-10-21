| Protocol | Accuracy | Macro F1 | Weighted F1 | Benign FPR (threat raised) | Attack detection (threat raised) |
|---|---|---|---|---|---|
| Random 80/20 (as reported) | 0.9882 | 0.7583 | 0.9895 | 0.2438% [0.1954%, 0.3041%] | 0.9331 |
| Chronological per class | 0.9765 | 0.7497 | 0.9785 | 0.3306% [0.3037%, 0.3600%] | 0.7954 |
| Deployed artifact on chronological test (not independent) | 0.9927 | 0.8796 | 0.9939 | 0.1012% [0.0868%, 0.1181%] | 0.9434 |
| Leave-out Monday | 0.9903 | 0.9952 | 0.9952 | 0.2300% [0.1725%, 0.3066%] | - |
| Leave-out Tuesday | 0.6858 | 0.2712 | 0.5583 | 0.0200% [0.0078%, 0.0514%] | 0.0000 |
| Leave-out Wednesday | 0.6640 | 0.2666 | 0.5330 | 0.0250% [0.0107%, 0.0585%] | 0.0027 |
| Leave-out Thursday | 0.9294 | 0.1935 | 0.9177 | 0.1600% [0.1253%, 0.2042%] | 0.0037 |
| Leave-out Friday | 0.8394 | 0.2981 | 0.7830 | 0.0183% [0.0102%, 0.0328%] | 0.0043 |

Score rule comparison (same models): attack detection / benign FPR

| Protocol | Threat raised: legacy blend | Threat raised: current | Block line: legacy blend | Block line: current |
|---|---|---|---|---|
| Random 80/20 | 0.62% / 0.0000% | 93.31% / 0.2437% | 0.00% / 0.0000% | 91.06% / 0.1469% |
| Chronological per class | 1.55% / 0.0000% | 79.54% / 0.3306% | 0.00% / 0.0000% | 78.44% / 0.1337% |
| Deployed artifact (not independent) | 4.49% / 0.0000% | 94.34% / 0.1012% | 0.00% / 0.0000% | 91.75% / 0.0812% |
| Leave-out Monday | - / 0.0000% | - / 0.2300% | - / 0.0000% | - / 0.0350% |
| Leave-out Tuesday | 0.00% / 0.0000% | 0.00% / 0.0200% | 0.00% / 0.0000% | 0.00% / 0.0200% |
| Leave-out Wednesday | 0.00% / 0.0000% | 0.27% / 0.0250% | 0.00% / 0.0000% | 0.19% / 0.0100% |
| Leave-out Thursday | 0.00% / 0.0000% | 0.37% / 0.1600% | 0.00% / 0.0000% | 0.00% / 0.0625% |
| Leave-out Friday | 0.00% / 0.0000% | 0.43% / 0.0183% | 0.00% / 0.0000% | 0.40% / 0.0150% |
