| Protocol | Accuracy | Macro F1 | Weighted F1 | Benign FPR (threat raised) | Attack detection (threat raised) |
|---|---|---|---|---|---|
| Chronological per class | 0.9765 | 0.7497 | 0.9785 | 0.2019% [0.1810%, 0.2251%] | 0.7881 |
| Leave-out Monday | 0.9903 | 0.9952 | 0.9952 | 0.0750% [0.0455%, 0.1237%] | - |
| Leave-out Tuesday | 0.6858 | 0.2712 | 0.5583 | 0.0200% [0.0078%, 0.0514%] | 0.0000 |
| Leave-out Wednesday | 0.6640 | 0.2666 | 0.5330 | 0.0100% [0.0027%, 0.0365%] | 0.0023 |
| Leave-out Thursday | 0.9294 | 0.1935 | 0.9177 | 0.0850% [0.0608%, 0.1188%] | 0.0014 |
| Leave-out Friday | 0.8394 | 0.2981 | 0.7830 | 0.0167% [0.0091%, 0.0307%] | 0.0042 |

Score rule comparison (same models): attack detection / benign FPR

| Protocol | Threat raised: legacy blend | Threat raised: current | Block line: legacy blend | Block line: current |
|---|---|---|---|---|
| Chronological per class | 0.00% / 0.0000% | 78.81% / 0.2019% | 0.00% / 0.0000% | 78.44% / 0.1337% |
| Leave-out Monday | - / 0.0000% | - / 0.0750% | - / 0.0000% | - / 0.0350% |
| Leave-out Tuesday | 0.00% / 0.0000% | 0.00% / 0.0200% | 0.00% / 0.0000% | 0.00% / 0.0200% |
| Leave-out Wednesday | 0.00% / 0.0000% | 0.23% / 0.0100% | 0.00% / 0.0000% | 0.19% / 0.0100% |
| Leave-out Thursday | 0.00% / 0.0000% | 0.14% / 0.0850% | 0.00% / 0.0000% | 0.00% / 0.0625% |
| Leave-out Friday | 0.00% / 0.0000% | 0.42% / 0.0167% | 0.00% / 0.0000% | 0.40% / 0.0150% |
