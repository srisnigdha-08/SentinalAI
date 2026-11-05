# Pipeline summary: xgb_cicids_v1 (xgboost)

- train.py random split (de-duplicated): {'accuracy': 0.9897, 'f1_weighted': 0.9907, 'f1_macro': 0.8738}
- chronological: macro F1 0.7718, at alert line 0.9: {'attack_detection': 0.9113, 'benign_fpr': 0.001587}
- leave-one-day-out attack detection: {'Monday': None, 'Tuesday': 0.0021, 'Wednesday': 0.069, 'Thursday': 0.8017, 'Friday': 0.1027}
- threshold validation selects 0.87 (test: {'line': 0.87, 'benign_fpr': 0.00145, 'benign_fpr_ci95': [0.001275, 0.001649], 'attack_detection': 0.9159})
