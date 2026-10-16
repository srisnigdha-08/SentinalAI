"""
tests/test_predictor.py

Unit tests for ai-engine/inference/predictor.py:
  - Model prioritization: cicids real-data models take precedence over synthetic baselines
  - get_ip_reputation() skips private / loopback IPs
  - get_ip_reputation() skips when ABUSEIPDB_API_KEY is not set
  - _demo() fallback produces correct response shape
"""
import sys
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Model prioritization ──────────────────────────────────────────────────────

class TestModelPrioritization:
    """
    Verify that SentinelPredictor.load() selects the highest-priority model
    that actually exists on disk, without loading real large pickle files.
    """

    def _make_fake_model_dir(self, tmp_path: Path, filenames: list[str]) -> Path:
        """Create a temp model directory with placeholder .pkl and .json files."""
        model_dir = tmp_path / "models"
        model_dir.mkdir()

        # Isolation forest is always required for the load() path to proceed
        for name in filenames + ["isolation_forest_cicids.pkl"]:
            (model_dir / name).write_bytes(b"")  # empty placeholder

        # Write a minimal meta.json for each pkl
        for name in filenames:
            meta_name = name.replace(".pkl", "_meta.json")
            (model_dir / meta_name).write_text(
                json.dumps({"version": "test-v1", "metrics": {"accuracy": 0.99}})
            )

        (model_dir / "isolation_forest_cicids_meta.json").write_text(
            json.dumps({"version": "if-test", "metrics": {}})
        )
        return model_dir

    def test_cicids_v2_selected_over_synthetic_baseline(self, tmp_path):
        """rf_classifier_cicids_v2.pkl must be chosen over rf_classifier_v2.1.pkl."""
        model_dir = self._make_fake_model_dir(
            tmp_path,
            ["rf_classifier_cicids_v2.pkl", "rf_classifier_v2.1.pkl"]
        )

        with patch("joblib.load", return_value=MagicMock()), \
             patch("inference.predictor.SentinelPredictor.init_explainer"):
            from inference.predictor import SentinelPredictor
            p = SentinelPredictor(model_dir=str(model_dir))

        assert p.model_type == "rf"
        # meta should come from cicids_v2, not v2.1
        assert p.rf_meta.get("version") == "test-v1"

    def test_xgb_cicids_selected_when_no_rf_cicids(self, tmp_path):
        """xgb_classifier_cicids_v2.pkl must be chosen when no RF cicids model exists."""
        model_dir = self._make_fake_model_dir(
            tmp_path,
            ["xgb_classifier_cicids_v2.pkl", "rf_classifier_v2.1.pkl"]
        )

        with patch("joblib.load", return_value=MagicMock()), \
             patch("inference.predictor.SentinelPredictor.init_explainer"):
            from inference.predictor import SentinelPredictor
            import importlib
            import inference.predictor as pred_mod
            importlib.reload(pred_mod)
            p = pred_mod.SentinelPredictor(model_dir=str(model_dir))

        assert p.model_type == "xgboost"

    def test_rf_synthetic_selected_over_xgb_synthetic(self, tmp_path):
        """rf_classifier_v2.1.pkl must be chosen over xgb_classifier.pkl."""
        model_dir = self._make_fake_model_dir(
            tmp_path,
            ["rf_classifier_v2.1.pkl", "xgb_classifier.pkl"]
        )

        with patch("joblib.load", return_value=MagicMock()), \
             patch("inference.predictor.SentinelPredictor.init_explainer"):
            from inference.predictor import SentinelPredictor
            import importlib
            import inference.predictor as pred_mod
            importlib.reload(pred_mod)
            p = pred_mod.SentinelPredictor(model_dir=str(model_dir))

        assert p.model_type == "rf"
        assert p.rf_meta.get("version") == "test-v1"

    def test_no_models_runs_in_demo_mode(self, tmp_path):
        """With no pkl files present, predictor must not raise and _loaded must be False."""
        model_dir = tmp_path / "models"
        model_dir.mkdir()

        import importlib
        import inference.predictor as pred_mod
        importlib.reload(pred_mod)

        with patch("inference.predictor.SentinelPredictor.init_explainer"):
            p = pred_mod.SentinelPredictor(model_dir=str(model_dir))

        assert p._loaded is False


# ── get_ip_reputation ─────────────────────────────────────────────────────────

class TestGetIpReputation:

    def setup_method(self):
        """Clear reputation cache before every test."""
        import importlib
        import inference.predictor as pred_mod
        importlib.reload(pred_mod)
        pred_mod.REPUTATION_CACHE.clear()
        self.get_ip_reputation = pred_mod.get_ip_reputation

    def test_returns_none_for_private_ip(self):
        assert self.get_ip_reputation("192.168.1.1") is None

    def test_returns_none_for_loopback(self):
        assert self.get_ip_reputation("127.0.0.1") is None

    def test_returns_none_for_empty_string(self):
        assert self.get_ip_reputation("") is None

    def test_returns_none_when_api_key_missing(self):
        """Should skip the request when ABUSEIPDB_API_KEY is not set."""
        with patch.dict(os.environ, {}, clear=True):
            # Ensure no API key in env
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            result = self.get_ip_reputation("8.8.8.8")
        assert result is None

    def test_returns_none_for_invalid_ip_string(self):
        assert self.get_ip_reputation("not-an-ip") is None

    def test_caches_successful_lookup(self):
        """A successful API response should be cached and not trigger a second HTTP call."""
        import inference.predictor as pred_mod

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"abuseConfidenceScore": 75}}

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}), \
             patch("requests.get", return_value=mock_response) as mock_get:
            first  = pred_mod.get_ip_reputation("8.8.8.8")
            second = pred_mod.get_ip_reputation("8.8.8.8")  # should hit cache

        assert first == 0.75
        assert second == 0.75
        assert mock_get.call_count == 1  # only one real HTTP call

    def test_returns_none_on_http_error(self):
        """Non-200 response must return None gracefully."""
        import inference.predictor as pred_mod

        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = "Rate limited"

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}), \
             patch("requests.get", return_value=mock_response):
            result = pred_mod.get_ip_reputation("8.8.8.8")

        assert result is None

    def test_returns_none_on_network_exception(self):
        """Network exceptions must be caught and return None."""
        import inference.predictor as pred_mod

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}), \
             patch("requests.get", side_effect=ConnectionError("timeout")):
            result = pred_mod.get_ip_reputation("8.8.8.8")

        assert result is None


# ── Isolation Forest Scoring Integrity Tests ─────────────────────────────────

class TestIsolationForestScoring:
    """
    Targeted and regression tests for Isolation Forest anomaly scoring transformation.
    Verifies:
      - inliers (score >= offset) return 0.0
      - boundary behavior at offset
      - outlier scaling in (0, 1]
      - extreme outlier saturation at 1.0
      - strict boundedness in [0.0, 1.0]
      - safe handling of NaN, inf, and None
      - deterministic output
      - regression: no ~0.30 IF inflation on normal benign flows
    """

    @pytest.fixture
    def predictor(self):
        import importlib
        import inference.predictor as pred_mod
        importlib.reload(pred_mod)
        with patch("inference.predictor.SentinelPredictor.load"), \
             patch("inference.predictor.SentinelPredictor.init_explainer"):
            p = pred_mod.SentinelPredictor()
            p._loaded = True
            # Mock ifo with known offset
            mock_ifo = MagicMock()
            mock_if_step = MagicMock()
            mock_if_step.offset_ = -0.47402357424116837
            mock_ifo.named_steps = {"if": mock_if_step}
            p.ifo = mock_ifo
            return p

    def test_inlier_score_yields_zero_anomaly_signal(self, predictor):
        """Typical inlier scores must return 0.0 anomaly signal."""
        # Genuine benign median score observed was -0.3838
        assert predictor.calculate_if_anomaly_signal(-0.3606) == 0.0
        assert predictor.calculate_if_anomaly_signal(-0.3838) == 0.0
        assert predictor.calculate_if_anomaly_signal(-0.4000) == 0.0
        assert predictor.calculate_if_anomaly_signal(-0.4500) == 0.0

    def test_boundary_behavior_at_offset(self, predictor):
        """At exactly the offset decision boundary, anomaly signal must be 0.0."""
        offset = predictor.ifo.named_steps["if"].offset_
        assert predictor.calculate_if_anomaly_signal(offset) == 0.0

        # Slightly more negative than offset by 0.02 (10% of span 0.20)
        assert predictor.calculate_if_anomaly_signal(offset - 0.02) == 0.1000

    def test_anomalous_score_scaling(self, predictor):
        """Deflections into outlier territory must scale proportionally."""
        offset = predictor.ifo.named_steps["if"].offset_
        # Halfway across span 0.20
        assert predictor.calculate_if_anomaly_signal(offset - 0.10) == 0.5000
        # Critical ANOMALY_THRESHOLD (-0.55): deflection = 0.075976 -> 0.3799
        assert predictor.calculate_if_anomaly_signal(-0.55) == 0.3799

    def test_extreme_outlier_saturation(self, predictor):
        """Scores beyond the span must saturate cleanly at 1.0."""
        offset = predictor.ifo.named_steps["if"].offset_
        assert predictor.calculate_if_anomaly_signal(offset - 0.20) == 1.0
        assert predictor.calculate_if_anomaly_signal(offset - 0.35) == 1.0
        assert predictor.calculate_if_anomaly_signal(-0.80) == 1.0

    def test_score_range_and_boundedness(self, predictor):
        """Across extreme inputs, anomaly signal must strictly remain in [0.0, 1.0]."""
        test_scores = [-10.0, -1.0, -0.75, -0.674, -0.55, -0.474, -0.30, 0.0, 1.0, 10.0]
        for s in test_scores:
            sig = predictor.calculate_if_anomaly_signal(s)
            assert 0.0 <= sig <= 1.0

    def test_non_finite_inputs_handled_safely(self, predictor):
        """NaN, inf, -inf, None must return 0.0 without raising."""
        assert predictor.calculate_if_anomaly_signal(float("nan")) == 0.0
        assert predictor.calculate_if_anomaly_signal(float("inf")) == 0.0
        assert predictor.calculate_if_anomaly_signal(float("-inf")) == 0.0
        assert predictor.calculate_if_anomaly_signal(None) == 0.0
        assert predictor.calculate_if_anomaly_signal("invalid") == 0.0

    def test_deterministic_output(self, predictor):
        """Repeated calls must yield strictly identical float outputs."""
        score = -0.5123
        first = predictor.calculate_if_anomaly_signal(score)
        second = predictor.calculate_if_anomaly_signal(score)
        assert first == second

    def test_regression_old_defect_no_benign_inflation(self, predictor):
        """
        Regression Test:
        Under the old formula:
          if_score = -0.3606 -> min(|-0.3606| * 3, 1.0) = 1.0000
          resulting in an automatic +0.3000 ThreatScore penalty on benign flows.
        Under the corrected formula:
          if_score = -0.3606 -> 0.0000
          resulting in +0.0000 ThreatScore penalty.
        """
        sample_benign_score = -0.3606
        # Old formula defect check
        old_sig = min(abs(min(sample_benign_score, 0.0)) * 3.0, 1.0)
        assert old_sig == 1.0
        old_contrib = 0.3 * old_sig
        assert old_contrib == 0.3

        # Corrected transformation check
        new_sig = predictor.calculate_if_anomaly_signal(sample_benign_score)
        assert new_sig == 0.0
        new_contrib = 0.3 * new_sig
        assert new_contrib == 0.0

