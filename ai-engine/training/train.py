#!/usr/bin/env python3
"""
SentinelAI Model Training
Usage:
  python training/train.py --synthetic --rows 20000
  python training/train.py --data datasets/cicids.csv
  python training/train.py --data datasets/cicids2017 --model-dir models --version rf_cicids_v3   # deployed recipe

Exact duplicate rows (same 53 features and label) are removed before the split, so no test row has an
identical copy in train (C2, docs/CRITICAL_FIXES_REPORT.md). The metadata records the CLI arguments,
parameters, split, row/class counts, dataset hashes and git commit needed to rebuild the artifact.
"""
import sys, os, time, json, joblib, argparse, warnings, hashlib, subprocess
import numpy as np
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler, FunctionTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, f1_score, classification_report
from datetime import datetime
from utils.features import FEATURE_NAMES, LABEL_MAP, LABEL_NAMES, LABEL_SOURCES, prepare_features, RAW_LABEL_TO_TARGET, CANDIDATES, log_transform_features
from utils.data_generator import generate
from monitoring.drift import benign_reference

warnings.filterwarnings("ignore")

RF_PARAMS = {"n_estimators":200,"max_depth":20,"min_samples_split":5,"min_samples_leaf":1,"class_weight":"balanced","n_jobs":-1,"random_state":42}
IF_PARAMS  = {"n_estimators":200,"contamination":0.1,"max_samples":"auto","random_state":42,"n_jobs":-1}

def smote_strategy(y):
    """SMOTE targets for the two thin classes: Malware Beacon (7) to >= 4,000 rows, XSS Attempt (6) to >= 1,500."""
    counts = dict(zip(*np.unique(y, return_counts=True)))
    return {c: max(int(counts[c]) + 1, target) for c, target in ((7, 4000), (6, 1500)) if c in counts}


def drop_duplicate_rows(X, y):
    """Keep the first occurrence of every identical (feature vector, label) row, preserving order."""
    rows = np.column_stack([X, y])
    _, first = np.unique(rows, axis=0, return_index=True)
    keep = np.sort(first)
    _, vec_first = np.unique(X[keep], axis=0, return_index=True)
    stats = {"rows_before": int(len(X)), "rows_after": int(len(keep)), "removed": int(len(X) - len(keep)),
             "conflicting_label_vectors": int(len(keep) - len(vec_first))}
    return X[keep], y[keep], stats


def file_sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def provenance(args, data_path):
    """What is needed to rebuild an artifact: CLI, code revision, libraries, input file hashes."""
    import sklearn
    try:
        git = lambda *a: subprocess.run(["git", *a], capture_output=True, text=True, cwd=Path(__file__).parent,
                                        timeout=10).stdout.strip()
        commit = git("rev-parse", "HEAD") or None
        dirty = bool(git("status", "--porcelain", "--", ".")) if commit else None
    except (OSError, subprocess.SubprocessError):
        commit = dirty = None
    files = []
    if data_path is not None:
        files = sorted(data_path.glob("*.csv")) if data_path.is_dir() else [data_path]
    return {"cli_args": {k: v for k, v in vars(args).items()}, "git_commit": commit, "git_dirty": dirty,
            "python": sys.version.split()[0], "sklearn": sklearn.__version__, "numpy": np.__version__,
            "data_sha256": {f.name: file_sha256(f) for f in files}}


def train(args):
    model_dir = Path(args.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    print("=" * 55)
    print("  SentinelAI Model Training")
    print("=" * 55)

    suffix = ""
    data_path = None
    if args.synthetic or not args.data:
        print(f"Generating {args.rows:,} synthetic samples...")
        df = generate(args.rows)
    else:
        import pandas as pd
        suffix = "_cicids"
        data_path = Path(args.data)
        if data_path.is_dir():
            csv_files = sorted(list(data_path.glob("*.csv")))
            print(f"Loading {len(csv_files)} CSV files from directory: {data_path}")
            
            # Memory-efficient raw class distribution scan
            print("Scanning raw labels to print distribution...")
            raw_counts = pd.Series(dtype=int)
            for csv_file in csv_files:
                header_df = pd.read_csv(csv_file, nrows=1)
                label_col = next((c for c in header_df.columns if c.strip().lower() == "label"), "Label")
                lbl_series = pd.read_csv(csv_file, usecols=[label_col])[label_col].astype(str).str.strip()
                raw_counts = raw_counts.add(lbl_series.value_counts(), fill_value=0)
                
            print("\nRaw Class Distribution (Before Mapping/Subsampling):")
            for k, v in raw_counts.sort_values(ascending=False).items():
                k_safe = str(k).encode('ascii', errors='backslashreplace').decode('ascii')
                print(f"  {k_safe}: {int(v):,}")
                
            unexpected = [lbl for lbl in raw_counts.index if lbl not in RAW_LABEL_TO_TARGET]
            if unexpected:
                print("\n[WARNING] Found unexpected labels:")
                for lbl in unexpected:
                    lbl_safe = str(lbl).encode('ascii', errors='backslashreplace').decode('ascii')
                    print(f"  {lbl_safe}: {int(raw_counts[lbl]):,}")
                    
            # Memory-efficient column-filtering and cleaning load
            print("\nLoading and cleaning CSV files memory-efficiently...")
            dfs = []
            for csv_file in csv_files:
                print(f"  Reading and cleaning: {csv_file.name}")
                # Read header to get columns in CSV
                header_df = pd.read_csv(csv_file, nrows=1)
                
                # Get list of needed columns
                needed_cols = ["label", "Label", "target_class"]
                for fn, cands in CANDIDATES.items():
                    for cand in cands:
                        needed_cols.append(cand)
                        
                # Match needed columns against header columns
                cols_to_use = []
                for cand in needed_cols:
                    matched = False
                    for h_col in header_df.columns:
                        h_col_stripped = h_col.strip()
                        if cand == h_col_stripped:
                            cols_to_use.append(h_col)
                            matched = True
                            break
                    if not matched:
                        cand_lower = cand.lower().replace("_", "").replace(" ", "").replace("/", "")
                        for h_col in header_df.columns:
                            h_col_norm = h_col.strip().lower().replace("_", "").replace(" ", "").replace("/", "")
                            if h_col_norm == cand_lower:
                                cols_to_use.append(h_col)
                                break
                                
                cols_to_use = list(set(cols_to_use))
                
                # Read only needed columns to prevent memory errors
                file_df = pd.read_csv(csv_file, usecols=cols_to_use)
                file_df.columns = file_df.columns.str.strip()
                
                label_col = next((c for c in file_df.columns if c.lower() == "label"), "Label")
                file_df["label"] = file_df[label_col].astype(str).str.strip()
                if label_col != "label" and label_col in file_df.columns:
                    file_df = file_df.drop(columns=[label_col])
                    
                file_df["target_class"] = file_df["label"].map(lambda x: RAW_LABEL_TO_TARGET.get(x, x))
                
                # Parse numeric features and drop NaN/inf
                feature_cols = [c for c in file_df.columns if c.lower() != "label" and c != "target_class"]
                for col in feature_cols:
                    file_df[col] = pd.to_numeric(file_df[col], errors='coerce')
                file_df = file_df.replace([float("inf"), float("-inf")], float("nan")).dropna(subset=feature_cols)
                
                # Per-file pre-subsampling to keep RAM footprint low
                pre_caps = {
                    "BENIGN": 15000,
                    "Port Scan": 10000,
                    "DDoS": 10000
                }
                sub_dfs = []
                for tc, grp in file_df.groupby("target_class"):
                    tc_str = str(tc)
                    if tc_str in pre_caps:
                        cap = pre_caps[tc_str]
                        sub_dfs.append(grp.sample(n=min(len(grp), cap), random_state=42))
                    else:
                        sub_dfs.append(grp)
                if sub_dfs:
                    file_df = pd.concat(sub_dfs, ignore_index=True)
                
                if len(file_df) > 0:
                    dfs.append(file_df)
                    
            df = pd.concat(dfs, ignore_index=True)
            
        else:
            print(f"Loading: {data_path}")
            df = pd.read_csv(data_path)
            df.columns = df.columns.str.strip()
            label_col = next((c for c in df.columns if c.lower() == "label"), "Label")
            df["label"] = df[label_col].astype(str).str.strip()
            if label_col != "label" and label_col in df.columns:
                df = df.drop(columns=[label_col])
                
            df["target_class"] = df["label"].map(lambda x: RAW_LABEL_TO_TARGET.get(x, x))
            
            feature_cols = [c for c in df.columns if c.lower() != "label" and c != "target_class"]
            for col in feature_cols:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            df = df.replace([float("inf"), float("-inf")], float("nan")).dropna(subset=feature_cols)

        # Print class distribution after cleanup
        print("\nClass Distribution after Cleaning:")
        clean_counts = df["target_class"].value_counts()
        for k, v in clean_counts.items():
            k_safe = str(k).encode('ascii', errors='backslashreplace').decode('ascii')
            print(f"  {k_safe}: {v:,}")

        # Capped Subsampling Strategy:
        # Keep all rows for classes with < 10,000 samples. Cap BENIGN at 100k, PortScan at 40k, DDoS at 40k.
        caps = {
            "BENIGN": 100000,
            "Port Scan": 40000,
            "DDoS": 40000
        }
        
        print("\nApplying Capped Subsampling Strategy:")
        subsampled_dfs = []
        for label_name, df_grp in df.groupby("target_class"):
            lbl_str = str(label_name)
            lbl_str_safe = lbl_str.encode('ascii', errors='backslashreplace').decode('ascii')
            if lbl_str in caps:
                cap = caps[lbl_str]
                sub_grp = df_grp.sample(n=min(len(df_grp), cap), random_state=42)
                subsampled_dfs.append(sub_grp)
                print(f"  Subsampled {lbl_str_safe}: {len(df_grp):,} -> {len(sub_grp):,}")
            else:
                subsampled_dfs.append(df_grp)
                print(f"  Kept all {lbl_str_safe}: {len(df_grp):,}")
                
        df = pd.concat(subsampled_dfs, ignore_index=True)
        df = df.drop(columns=["target_class"])

        print("\nFinal Dataset Class Distribution for Training:")
        final_counts = df["label"].map(lambda x: RAW_LABEL_TO_TARGET.get(x, x)).value_counts()
        for k, v in final_counts.items():
            k_safe = str(k).encode('ascii', errors='backslashreplace').decode('ascii')
            print(f"  {k_safe}: {v:,}")
        print(f"Total Rows: {len(df):,}")

    # Fail instead of training on silently zero-filled columns (renamed/missing CSV headers). The synthetic
    # generator has no init-window/active/idle/down-up columns by design, so the check applies to real data.
    X, y = prepare_features(df, max_missing=0 if suffix else None)
    X, y, dedup = drop_duplicate_rows(X, y)
    print(f"Removed {dedup['removed']:,} exact duplicate rows ({dedup['removed'] / max(1, dedup['rows_before']):.1%}); "
          f"{dedup['conflicting_label_vectors']:,} feature vectors carry more than one label and are kept")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Train: {len(X_train):,} | Test: {len(X_test):,}")
    class_counts = {split: {LABEL_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(labels, return_counts=True))}
                    for split, labels in (("train", y_train), ("test", y_test))}

    # Pre-SMOTE training rows: cross-validation resamples inside each fold instead (M8)
    X_train_cv, y_train_cv = X_train, y_train
    if args.smote:
        unique_cls, counts_cls = np.unique(y_train, return_counts=True)
        counts_dict = dict(zip(unique_cls, counts_cls))
        sampling_strategy = smote_strategy(y_train)
            
        print("\nOriginal class counts in y_train:")
        for k, v in counts_dict.items():
            print(f"  {LABEL_NAMES[k]} (label {k}): {v:,}")
            
        print(f"\nApplying SMOTE for rare classes. Targets: Malware Beacon -> {sampling_strategy.get(7)}, XSS Attempt -> {sampling_strategy.get(6)}")
        from imblearn.over_sampling import SMOTE
        smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        
        unique_res, counts_res = np.unique(y_train, return_counts=True)
        counts_res_dict = dict(zip(unique_res, counts_res))
        print("\nResampled class counts in y_train:")
        for k, v in counts_res_dict.items():
            print(f"  {LABEL_NAMES[k]} (label {k}): {v:,}")
            
        orig_mb = counts_dict.get(7, 0)
        new_mb = counts_res_dict.get(7, 0)
        mb_ratio = (new_mb - orig_mb) / max(orig_mb, 1)
        print(f"  Malware Beacon: {orig_mb} real, {new_mb - orig_mb} synthetic (ratio: {mb_ratio:.2f} synthetic per 1 real)")
        
        orig_xss = counts_dict.get(6, 0)
        new_xss = counts_res_dict.get(6, 0)
        xss_ratio = (new_xss - orig_xss) / max(orig_xss, 1)
        print(f"  XSS Attempt: {orig_xss} real, {new_xss - orig_xss} synthetic (ratio: {xss_ratio:.2f} synthetic per 1 real)")

    # Ensure all classes present in the dataset are represented in y_train to satisfy classifier requirements.
    # We exclude classes that have zero support in both train and test splits (such as class 10, Data Exfiltration).
    missing_classes = (set(np.unique(y_train)) | set(np.unique(y_test))) - set(y_train)
    if missing_classes:
        print(f"  Adding dummy samples for missing classes to train set: {missing_classes}")
        dummy_X = np.zeros((len(missing_classes), X_train.shape[1]))
        dummy_y = np.array(list(missing_classes))
        X_train = np.vstack([X_train, dummy_X])
        y_train = np.concatenate([y_train, dummy_y])

    # Model Selection (Random Forest, XGBoost, or Stacking)
    if args.model == "xgboost":
        model_name = "XGBoost"
    elif args.model == "stacking":
        model_name = "StackingClassifier"
    else:
        model_name = "Random Forest"
        
    print(f"\nTraining {model_name}...")
    t0 = time.time()
    
    fit_params = {}
    should_save = True
    
    if args.model == "xgboost":
        from xgboost import XGBClassifier
        from sklearn.utils.class_weight import compute_sample_weight
        sample_weights = compute_sample_weight("balanced", y_train)
        fit_params["xgb__sample_weight"] = sample_weights
        
        XGB_PARAMS = {"n_estimators":200,"max_depth":6,"learning_rate":0.1,"random_state":42,"n_jobs":-1,"eval_metric":"mlogloss"}
        clf = XGBClassifier(**XGB_PARAMS)
        pipe = Pipeline([("scaler", StandardScaler()), ("xgb", clf)])
        model_type_str = "XGBClassifier"
        if suffix:
            pkl_name = "xgb_classifier_cicids.pkl"
            meta_name = "xgb_classifier_cicids_meta.json"
            version_str = "xgb_cicids_v1.0"
        else:
            pkl_name = "xgb_classifier.pkl"
            meta_name = "xgb_classifier_meta.json"
            version_str = "xgb_v1.0"
            
    elif args.model == "stacking":
        from sklearn.ensemble import StackingClassifier
        from sklearn.linear_model import LogisticRegression
        from xgboost import XGBClassifier
        from sklearn.utils.class_weight import compute_sample_weight
        
        rf_base = RandomForestClassifier(**RF_PARAMS)
        xgb_base = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric="mlogloss")
        
        estimators = [
            ("rf", rf_base),
            ("xgb", xgb_base)
        ]
        stack = StackingClassifier(
            estimators=estimators,
            final_estimator=LogisticRegression(max_iter=1000),
            cv=3,
            n_jobs=-1
        )
        pipe = Pipeline([("scaler", StandardScaler()), ("stacking", stack)])
        
        sample_weights = compute_sample_weight("balanced", y_train)
        fit_params["stacking__sample_weight"] = sample_weights
        
        model_type_str = "StackingClassifier"
        if suffix:
            pkl_name = "stacking_classifier_cicids.pkl"
            meta_name = "stacking_classifier_cicids_meta.json"
            version_str = "stack_cicids_v1.0"
        else:
            pkl_name = "stacking_classifier.pkl"
            meta_name = "stacking_classifier_meta.json"
            version_str = "stack_v1.0"
            
    else:  # Random Forest
        clf = RandomForestClassifier(**RF_PARAMS)
        pipe = Pipeline([("scaler", StandardScaler()), ("rf", clf)])
        model_type_str = "RandomForestClassifier"
        if suffix:
            pkl_name = "rf_classifier_cicids_v2.pkl"
            meta_name = "rf_classifier_cicids_v2_meta.json"
            version_str = "rf_cicids_v2.0"
        else:
            pkl_name = "rf_classifier_v2.1.pkl"
            meta_name = "rf_classifier_v2.1_meta.json"
            version_str = "v2.1"
            
        if args.tune:
            baseline_macro_f1 = 0.8468
            baseline_acc = 0.9853
            baseline_f1_weighted = 0.9870
            
            baseline_path = model_dir / pkl_name
            if baseline_path.exists():
                try:
                    print(f"\nLoading existing baseline model from {baseline_path} for comparison...")
                    baseline_pipe = joblib.load(baseline_path)
                    y_pred_baseline = baseline_pipe.predict(X_test)
                    baseline_acc = accuracy_score(y_test, y_pred_baseline)
                    baseline_f1_weighted = f1_score(y_test, y_pred_baseline, average="weighted", zero_division=0)
                    baseline_macro_f1 = f1_score(y_test, y_pred_baseline, average="macro", zero_division=0)
                    print(f"  Baseline Model (on test set): Acc = {baseline_acc:.4f}, Weighted F1 = {baseline_f1_weighted:.4f}, Macro F1 = {baseline_macro_f1:.4f}")
                except Exception as e:
                    print(f"  Could not load baseline model: {e}. Using default baseline metrics (Acc: 0.9853, Macro F1: 0.8468).")
            else:
                print(f"\nNo baseline model found at {baseline_path}. Using default baseline metrics (Acc: 0.9853, Macro F1: 0.8468).")
                
            print("\nRunning RandomizedSearchCV for Random Forest hyperparameter tuning...")
            param_dist = {
                "rf__n_estimators": [200, 400, 600],
                "rf__max_depth": [15, 20, 30, None],
                "rf__min_samples_leaf": [1, 2, 4]
            }
            search = RandomizedSearchCV(
                pipe,
                param_distributions=param_dist,
                n_iter=15,
                scoring="f1_macro",
                cv=3,
                random_state=42,
                n_jobs=-1
            )
            search_t0 = time.time()
            search.fit(X_train, y_train)
            print(f"  Tuning complete in {time.time()-search_t0:.1f}s. Best params: {search.best_params_}")
            pipe = search.best_estimator_
            
            y_pred_tuned = pipe.predict(X_test)
            tuned_acc = accuracy_score(y_test, y_pred_tuned)
            tuned_f1_weighted = f1_score(y_test, y_pred_tuned, average="weighted", zero_division=0)
            tuned_f1_macro = f1_score(y_test, y_pred_tuned, average="macro", zero_division=0)
            print(f"\nTuned RF Evaluation on Test Set: Acc = {tuned_acc:.4f}, Weighted F1 = {tuned_f1_weighted:.4f}, Macro F1 = {tuned_f1_macro:.4f}")
            
            if tuned_f1_macro <= baseline_macro_f1:
                print(f"\nTuned RF Macro F1 ({tuned_f1_macro:.4f}) does NOT improve over baseline model Macro F1 ({baseline_macro_f1:.4f}).")
                print("Tuning did NOT help. We will NOT overwrite the existing production model.")
                should_save = False
            else:
                print(f"\nTuned RF Macro F1 ({tuned_f1_macro:.4f}) IMPROVED over baseline model Macro F1 ({baseline_macro_f1:.4f})!")
                print("We will save this tuned model as the new production model.")

    if not (args.model == "rf" and args.tune):
        pipe.fit(X_train, y_train, **fit_params)
        
    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    print(f"\nEvaluation of Trained Model on Real Test Set:")
    print(f"  Accuracy: {acc:.4f} | Weighted F1: {f1_weighted:.4f} | Macro F1: {f1_macro:.4f} | Time: {time.time()-t0:.1f}s")

    # Print confusion matrix and classification report
    from sklearn.metrics import confusion_matrix
    print("\nClassification Report:")
    unique_y = np.unique(y_test)
    target_names = [LABEL_NAMES[i] for i in unique_y]
    print(classification_report(y_test, y_pred, labels=unique_y, target_names=target_names, zero_division=0))
    
    print("\nConfusion Matrix (Rows: Actual, Cols: Predicted):")
    conf_mat = confusion_matrix(y_test, y_pred)
    print("Class names mapping:", {i: LABEL_NAMES[i] for i in unique_y})
    print(conf_mat)

    # Print feature importances sorted descending
    try:
        if args.model == "xgboost":
            importances = pipe.named_steps["xgb"].feature_importances_
            indices = np.argsort(importances)[::-1]
            print("\nFeature Importances (Sorted Descending):")
            for f in range(len(FEATURE_NAMES)):
                print(f"  {f+1}. {FEATURE_NAMES[indices[f]]}: {importances[indices[f]]:.6f}")
        elif args.model == "rf":
            importances = pipe.named_steps["rf"].feature_importances_
            indices = np.argsort(importances)[::-1]
            print("\nFeature Importances (Sorted Descending):")
            for f in range(len(FEATURE_NAMES)):
                print(f"  {f+1}. {FEATURE_NAMES[indices[f]]}: {importances[indices[f]]:.6f}")
        else:
            print("\n[INFO] Feature importances are not available for StackingClassifier.")
    except Exception as e:
        print(f"  Could not print feature importances: {e}")

    # Optional K-Fold Cross Validation
    if args.cv:
        print("\n" + "="*55)
        print("  Running 5-Fold Stratified Cross-Validation (training split only, same recipe per fold)")
        print("="*55)
        from sklearn.model_selection import StratifiedKFold
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        
        fold_accs = []
        fold_f1_macros = []
        class_f1s = {i: [] for i in range(11)}
        
        # Folds come from the training split only, so the held-out test rows never influence CV, and each fold
        # gets the deployed recipe: SMOTE (when --smote) is fitted on that fold's training part only (M8).
        for fold, (train_idx, val_idx) in enumerate(skf.split(X_train_cv, y_train_cv)):
            X_tr, X_val = X_train_cv[train_idx], X_train_cv[val_idx]
            y_tr, y_val = y_train_cv[train_idx], y_train_cv[val_idx]
            if args.smote:
                from imblearn.over_sampling import SMOTE
                X_tr, y_tr = SMOTE(sampling_strategy=smote_strategy(y_tr), random_state=42).fit_resample(X_tr, y_tr)

            # Same rule as the final model: a dummy row only for a class present in validation but not in training
            missing_tr = set(y_val) - set(y_tr)
            if missing_tr:
                dummy_X_cv = np.zeros((len(missing_tr), X_tr.shape[1]))
                dummy_y_cv = np.array(list(missing_tr))
                X_tr = np.vstack([X_tr, dummy_X_cv])
                y_tr = np.concatenate([y_tr, dummy_y_cv])
                
            fold_fit_params = {}
            if args.model == "xgboost":
                from xgboost import XGBClassifier
                from sklearn.utils.class_weight import compute_sample_weight
                sample_weights_cv = compute_sample_weight("balanced", y_tr)
                fold_fit_params["xgb__sample_weight"] = sample_weights_cv
                fold_clf = XGBClassifier(**XGB_PARAMS)
                fold_pipe = Pipeline([("scaler", StandardScaler()), ("xgb", fold_clf)])
            elif args.model == "stacking":
                from sklearn.ensemble import StackingClassifier
                from sklearn.linear_model import LogisticRegression
                from xgboost import XGBClassifier
                from sklearn.utils.class_weight import compute_sample_weight
                sample_weights_cv = compute_sample_weight("balanced", y_tr)
                fold_fit_params["stacking__sample_weight"] = sample_weights_cv
                
                rf_base = RandomForestClassifier(**RF_PARAMS)
                xgb_base = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric="mlogloss")
                stack = StackingClassifier(estimators=[("rf", rf_base), ("xgb", xgb_base)], final_estimator=LogisticRegression(max_iter=1000), cv=3, n_jobs=-1)
                fold_pipe = Pipeline([("scaler", StandardScaler()), ("stacking", stack)])
            else:
                current_rf_params = RF_PARAMS.copy()
                if args.tune and 'search' in locals():
                    best_params = search.best_params_
                    for k, val in best_params.items():
                        current_rf_params[k.replace("rf__", "")] = val
                fold_clf = RandomForestClassifier(**current_rf_params)
                fold_pipe = Pipeline([("scaler", StandardScaler()), ("rf", fold_clf)])
                
            fold_pipe.fit(X_tr, y_tr, **fold_fit_params)
            y_pred_val = fold_pipe.predict(X_val)
            
            fold_acc = accuracy_score(y_val, y_pred_val)
            fold_f1_macro = f1_score(y_val, y_pred_val, average="macro", zero_division=0)
            
            fold_accs.append(fold_acc)
            fold_f1_macros.append(fold_f1_macro)
            
            fold_f1_per_class = f1_score(y_val, y_pred_val, average=None, zero_division=0)
            unique_val_classes = np.unique(y_val)
            for c in range(11):
                if c in unique_val_classes:
                    idx = np.where(unique_val_classes == c)[0][0]
                    class_f1s[c].append(fold_f1_per_class[idx])
                else:
                    class_f1s[c].append(0.0)
                    
            print(f"  Fold {fold+1}: Accuracy = {fold_acc:.4f}, Macro F1 = {fold_f1_macro:.4f}")
            
        print(f"\nCV Mean Metrics:")
        print(f"  Accuracy: {np.mean(fold_accs):.4f} ± {np.std(fold_accs):.4f}")
        print(f"  Macro F1: {np.mean(fold_f1_macros):.4f} ± {np.std(fold_f1_macros):.4f}")
        
        print("\nPer-Class F1-scores across folds:")
        for c in range(11):
            c_name = LABEL_NAMES[c]
            c_f1s = class_f1s[c]
            print(f"  {c_name}: {np.mean(c_f1s):.4f} ± {np.std(c_f1s):.4f}")

    if args.version:
        prefix = {"XGBClassifier": "xgb_classifier", "StackingClassifier": "stacking_classifier"}.get(model_type_str, "rf_classifier")
        pkl_name, meta_name, version_str = f"{prefix}_{args.version}.pkl", f"{prefix}_{args.version}_meta.json", args.version
        if (model_dir / pkl_name).exists():
            raise SystemExit(f"Refusing to overwrite existing model file {model_dir / pkl_name}")

    if should_save:
        model_path = model_dir / pkl_name
        joblib.dump(pipe, model_path)
        meta = {"model_type":model_type_str,"version":version_str,"trained_at":datetime.utcnow().isoformat(),
                "n_features":len(FEATURE_NAMES),"feature_names":FEATURE_NAMES,
                "classes":{str(k):v for k,v in LABEL_MAP.items()},
                "metrics":{"accuracy":round(acc,4),"f1_weighted":round(f1_weighted,4),"f1_macro":round(f1_macro,4)},
                "evaluation":{"split":"stratified_random_80_20","random_state":42,"deduplicated":True,
                              "independent_holdout":False,
                              "note":"Random row split; see evaluation/day_holdout_eval.py for chronological and leave-one-day-out results"},
                "params":{k: v for k, v in pipe.get_params().items() if "__" in k and isinstance(v, (int, float, str, bool, type(None)))
                          and not (isinstance(v, float) and not np.isfinite(v))},
                "smote":bool(args.smote),"deduplication":dedup,"class_counts":class_counts,
                "label_sources":LABEL_SOURCES,
                "drift_reference":benign_reference(X_train[y_train == 0]),
                "provenance":provenance(args, data_path)}
        with open(model_dir / meta_name,"w") as f:
            json.dump(meta, f, indent=2)
        print(f"\nModel saved to {model_path}")
    else:
        print("\n[INFO] Saving/overwriting was skipped because tuning did not yield a macro F1 improvement.")

    # Evaluate existing synthetic model side-by-side if training on real data
    if suffix == "_cicids":
        syn_model_name = "xgb_classifier.pkl" if args.model == "xgboost" else "rf_classifier_v2.1.pkl"
        syn_model_path = model_dir / syn_model_name
        if syn_model_path.exists():
            print("\n" + "="*55)
            print("  Evaluating Synthetic Model on Real Test Set")
            print("="*55)
            try:
                syn_pipe = joblib.load(syn_model_path)
                y_pred_syn = syn_pipe.predict(X_test)
                acc_syn = accuracy_score(y_test, y_pred_syn)
                f1_syn_weighted = f1_score(y_test, y_pred_syn, average="weighted", zero_division=0)
                f1_syn_macro = f1_score(y_test, y_pred_syn, average="macro", zero_division=0)
                print(f"Synthetic Model on Real Test Set:")
                print(f"  Accuracy: {acc_syn:.4f} | Weighted F1: {f1_syn_weighted:.4f} | Macro F1: {f1_syn_macro:.4f}")
                
                print("\nClassification Report (Synthetic Model):")
                print(classification_report(y_test, y_pred_syn, labels=unique_y, target_names=target_names, zero_division=0))
                
                print("\nConfusion Matrix (Synthetic Model):")
                print(confusion_matrix(y_test, y_pred_syn, labels=unique_y))
            except Exception as e:
                print(f"  Error loading/evaluating synthetic model: {e}")
        else:
            print(f"\n[INFO] Synthetic model not found at {syn_model_path} to compare.")

    # Isolation Forest (benign only)
    print("\nTraining Isolation Forest...")
    t0 = time.time()
    X_benign = X_train[y_train == 0]
    ifo = Pipeline([("scaler", StandardScaler()), ("if", IsolationForest(**IF_PARAMS))])
    ifo.fit(X_benign)
    print(f"  Trained on {len(X_benign):,} benign samples | Time: {time.time()-t0:.1f}s")

    if args.version:
        if_path = model_dir / f"isolation_forest_{args.version}.pkl"
        if_meta_path = model_dir / f"isolation_forest_{args.version}_meta.json"
        if if_path.exists():
            raise SystemExit(f"Refusing to overwrite existing model file {if_path}")
    elif suffix:
        if_path = model_dir / "isolation_forest_cicids.pkl"
        if_meta_path = model_dir / "isolation_forest_cicids_meta.json"
    else:
        if_path = model_dir / "isolation_forest_v1.4.pkl"
        if_meta_path = model_dir / "isolation_forest_v1.4_meta.json"

    joblib.dump(ifo, if_path)
    with open(if_meta_path,"w") as f:
        json.dump({"model_type":"IsolationForest","version":args.version or ("v1.4_cicids" if suffix else "v1.4"),"trained_at":datetime.utcnow().isoformat(),
                   "n_features":len(FEATURE_NAMES),"feature_names":FEATURE_NAMES,"params":IF_PARAMS,"benign_training_rows":int(len(X_benign)),
                   "provenance":provenance(args, data_path)},f,indent=2)

    print(f"\nModels saved to {model_dir}/")
    print("=" * 55)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=str, default=None)
    p.add_argument("--synthetic", action="store_true")
    p.add_argument("--rows", type=int, default=20000)
    p.add_argument("--model-dir", type=str, default="models")
    p.add_argument("--model", type=str, choices=["rf", "xgboost", "stacking"], default="rf")
    p.add_argument("--cv", action="store_true", help="Run 5-Fold Stratified Cross-Validation")
    p.add_argument("--tune", action="store_true", help="Run hyperparameter tuning (RF only)")
    p.add_argument("--smote", action="store_true", help="Apply SMOTE to rare classes in training data")
    p.add_argument("--version", type=str, default=None,
                   help="Write <model>_<version>.pkl / isolation_forest_<version>.pkl (never overwrites); register with training/register_model.py")
    train(p.parse_args())
