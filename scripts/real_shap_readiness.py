"""Read-only genuine RF/IF/SHAP smoke check; no API, persistence, training or learning."""
import json
import math
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ['ABUSEIPDB_API_KEY'] = ''
sys.path.insert(0, str(ROOT / 'ai-engine'))
from inference.predictor import SentinelPredictor
from utils.features import FEATURE_NAMES

samples = json.loads((ROOT / '.test-runtime/native-readiness-20261014-01/evidence/run-1791983891431/samples.json').read_text())
predictor = SentinelPredictor(model_dir=str(ROOT / 'ai-engine/models'))
assert predictor._loaded and predictor.explainer is not None, 'Real models or SHAP explainer unavailable'
evidence = []
for sample in [samples[0], samples[-1]]:
    plain = predictor.predict(sample, explain=False)
    result = predictor.predict(sample, explain=True)
    explanation = result['featureImportance']
    assert len(explanation) == 5, 'Genuine explanation is empty or incomplete'
    assert all(item['feature'] in FEATURE_NAMES and math.isfinite(item['contribution']) for item in explanation)
    assert result['predictedClass'] == plain['predictedClass'] and result['threatScore'] == plain['threatScore'] and result['action'] == plain['action']
    evidence.append({'provenance': sample['provenance'], 'class': result['predictedClass'],
                     'threatScore': result['threatScore'], 'action': result['action'],
                     'featureImportance': explanation})
output = ROOT / '.test-runtime/master-native-20261014-80f776da/real-shap-smoke.json'
with output.open('x', encoding='utf-8') as stream:
    json.dump({'passed': True, 'category': 'real models, offline, read-only', 'cases': evidence}, stream, indent=2)
print(json.dumps({'passed': True, 'realFlows': len(evidence), 'explanationsPerFlow': 5, 'predictionSemanticsUnchanged': True}))
