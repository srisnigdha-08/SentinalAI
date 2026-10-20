| Protocol | Accuracy | Macro F1 | Weighted F1 | Benign FPR (threat raised) | Attack detection (threat raised) |
|---|---|---|---|---|---|
| Random 80/20 (as reported) | 0.9869 | 0.8778 | 0.9884 | 0.4250% [0.3594%, 0.5025%] | 0.9773 |
| Chronological per class | 0.9757 | 0.7390 | 0.9796 | 0.4962% [0.4630%, 0.5319%] | 0.8967 |
| Deployed artifact on chronological test (not independent) | 0.9875 | 0.8497 | 0.9908 | 0.6475% [0.6094%, 0.6880%] | 0.9861 |
| Leave-out Monday | 0.9920 | 0.9960 | 0.9960 | 0.1950% [0.1427%, 0.2664%] | - |
| Leave-out Tuesday | 0.5892 | 0.2472 | 0.4384 | 0.0600% [0.0343%, 0.1049%] | 0.0001 |
| Leave-out Wednesday | 0.6616 | 0.2656 | 0.5310 | 0.1250% [0.0847%, 0.1845%] | 0.0003 |
| Leave-out Thursday | 0.9350 | 0.1935 | 0.9157 | 0.5375% [0.4704%, 0.6141%] | 0.0000 |
| Leave-out Friday | 0.7520 | 0.2856 | 0.6611 | 0.0233% [0.0139%, 0.0392%] | 0.0023 |

Score rule comparison (same models): attack detection / benign FPR

| Protocol | Threat raised: legacy blend | Threat raised: current | Block line: legacy blend | Block line: current |
|---|---|---|---|---|
| Random 80/20 | 23.24% / 0.0125% | 97.73% / 0.4250% | 4.73% / 0.0000% | 93.62% / 0.1187% |
| Chronological per class | 29.41% / 0.0294% | 89.67% / 0.4962% | 4.99% / 0.0000% | 86.51% / 0.0463% |
| Deployed artifact (not independent) | 20.49% / 0.0275% | 98.61% / 0.6475% | 6.71% / 0.0000% | 95.41% / 0.0700% |
| Leave-out Monday | - / 0.0100% | - / 0.1950% | - / 0.0000% | - / 0.0250% |
| Leave-out Tuesday | 0.00% / 0.0200% | 0.01% / 0.0600% | 0.00% / 0.0000% | 0.00% / 0.0200% |
| Leave-out Wednesday | 0.00% / 0.0000% | 0.03% / 0.1250% | 0.00% / 0.0000% | 0.00% / 0.0100% |
| Leave-out Thursday | 0.00% / 0.0400% | 0.00% / 0.5375% | 0.00% / 0.0000% | 0.00% / 0.1675% |
| Leave-out Friday | 0.21% / 0.0067% | 0.23% / 0.0233% | 0.00% / 0.0000% | 0.01% / 0.0050% |
