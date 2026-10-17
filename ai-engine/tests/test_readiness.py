"""Regression checks for trustworthy inference and isolated evaluation."""
import os
from unittest.mock import patch, MagicMock
import numpy as np
import pytest
os.environ['SENTINEL_KEY'] = 'test-sentinel-secret-key-12345'
from inference.errors import ModelUnavailableError
from inference.predictor import SentinelPredictor
from inference.main import app, Record
from fastapi.testclient import TestClient

def test_missing_models_never_generate_predictions(tmp_path):
    predictor = SentinelPredictor(tmp_path)
    for method in (predictor.predict, predictor.predict_from_honeypot):
        with pytest.raises(ModelUnavailableError):
            method({})

def test_classifier_error_never_becomes_benign():
    with patch.object(SentinelPredictor, 'load'):
        predictor = SentinelPredictor()
    predictor._loaded = True
    predictor.rf = MagicMock()
    predictor.rf.predict.side_effect = ValueError('broken model')
    with pytest.raises(ModelUnavailableError):
        predictor.predict({})

@pytest.mark.parametrize('field', ['flow_duration', 'active_mean', 'init_win_bytes_forward'])
@pytest.mark.parametrize('value', ['NaN', 'Infinity', '-Infinity', None, 'bad'])
def test_nonfinite_features_rejected(field, value):
    with pytest.raises(ValueError):
        Record(**{field: value})

def test_readiness_and_removed_simulation():
    with patch('inference.main.predictor', None):
        client = TestClient(app)
        assert client.get('/health').status_code == 200
        assert client.get('/ready').status_code == 503
        assert client.post('/predict/simulate').status_code == 404

def test_backend_owned_prediction_suppresses_notification():
    model = MagicMock()
    model.predict.return_value = {'threatScore': 0.95, 'predictedClass': 'DDoS', 'action': 'BLOCK'}
    with patch('inference.main.predictor', model), patch('inference.main._notify') as notify:
        response = TestClient(app).post('/predict/internal', json={},
            headers={'X-API-Key': os.environ['SENTINEL_KEY']})
        assert response.status_code == 200
        notify.assert_not_called()

def test_actual_artifacts_and_shap():
    from pathlib import Path
    predictor = SentinelPredictor(Path(__file__).resolve().parents[1] / 'models')
    assert predictor._loaded, 'Supplied RF and IF must load for acceptance'
    assert predictor.rf.n_features_in_ == predictor.ifo.n_features_in_ == 53
    result = predictor.predict({'timestamp': '2026-10-13T12:00:00+05:30', 'flow_duration': 1200.0}, explain=True)
    assert len(result['featureVector']) == 53
    assert np.isfinite(result['featureVector']).all()
    assert len(result['featureImportance']) == 5
    assert all(np.isfinite(x['contribution']) for x in result['featureImportance'])
    score = result['threatScore']
    assert 0 <= score <= 1
    assert result['action'] == ('BLOCK' if score >= .92 else 'MONITOR' if score >= .70 else 'ALLOW')

def test_learning_state_preserves_shipped_artifact(tmp_path, monkeypatch):
    from inference import deception
    import json
    models = tmp_path / 'models'
    models.mkdir()
    seed = models / 'q_table.json'
    original = json.dumps({'episode_count': 7}).encode()
    seed.write_bytes(original)
    target = tmp_path / 'runtime' / 'q_table.json'
    monkeypatch.setenv('MODEL_DIR', str(models))
    monkeypatch.setenv('Q_TABLE_PATH', str(target))
    monkeypatch.setattr(deception, '_scorer', None)
    assert deception.get_scorer().learner.episode_count == 7
    deception.save_scorer()
    assert seed.read_bytes() == original
    assert target.exists()

def test_q_table_path_pointing_to_seed_redirects_to_runtime(tmp_path, monkeypatch):
    from inference import deception
    from pathlib import Path
    import json
    models = tmp_path / 'models'
    models.mkdir()
    seed = models / 'q_table.json'
    original = json.dumps({'episode_count': 42}).encode()
    seed.write_bytes(original)
    runtime_dir = tmp_path / 'runtime'
    runtime_dir.mkdir(parents=True, exist_ok=True)
    default_runtime_target = runtime_dir / 'q_table.json'

    # Intentionally point Q_TABLE_PATH directly at the baseline seed artifact
    monkeypatch.setenv('MODEL_DIR', str(models))
    monkeypatch.setenv('Q_TABLE_PATH', str(seed))
    monkeypatch.setenv('DEFAULT_RUNTIME_Q_TABLE_PATH', str(default_runtime_target))
    monkeypatch.setattr(deception, 'DEFAULT_RUNTIME_Q_TABLE_PATH', str(default_runtime_target))
    monkeypatch.setattr(deception, '_scorer', None)

    scorer = deception.get_scorer()
    # Scorer path must have been redirected away from seed to default runtime path in tmp_path
    assert Path(scorer.learner.q_table_path).resolve() != seed.resolve()
    assert Path(scorer.learner.q_table_path).resolve() == default_runtime_target.resolve()
    scorer.learner.episode_count = 99
    deception.save_scorer()

    # Seed baseline must remain completely unmodified
    assert seed.read_bytes() == original
    assert default_runtime_target.exists()

