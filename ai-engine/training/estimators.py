"""Estimators shared by evaluation and retraining (importable path, so pickles that contain them stay loadable)."""
import numpy as np

XGB_PARAMS = {"n_estimators": 200, "max_depth": 6, "learning_rate": 0.1, "random_state": 42, "n_jobs": -1,
              "eval_metric": "mlogloss"}  # same as training/train.py --model xgboost


class EncodedXGB:
    """XGBClassifier on label-encoded targets (a leave-one-day-out fold can miss classes, and XGBoost needs
    contiguous 0..k-1 labels), exposing the original labels as classes_; balanced sample weights as in train.py.
    The fitted booster is model_ (SHAP's TreeExplainer uses it directly)."""

    def __init__(self, **params):
        self.params = params

    def fit(self, X, y):
        from xgboost import XGBClassifier
        from sklearn.utils.class_weight import compute_sample_weight
        self.classes_ = np.unique(y)
        encoded = np.searchsorted(self.classes_, y)
        self.model_ = XGBClassifier(**self.params).fit(X, encoded, sample_weight=compute_sample_weight("balanced", y))
        self.n_features_in_ = X.shape[1]
        return self

    def predict_proba(self, X):
        return self.model_.predict_proba(X)

    def predict(self, X):
        return self.classes_[self.predict_proba(X).argmax(axis=1)]
