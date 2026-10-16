"""Start an isolated native AI process; evaluate real dataset rows without persistence."""
from pathlib import Path
import os, sys, time, subprocess, socket, secrets, json, ast
import httpx
import pandas as pd
ROOT = Path(__file__).resolve().parents[1]
AI = ROOT / 'ai-engine'
sys.path.insert(0, str(AI))
from utils.features import prepare_features, FEATURE_NAMES
runtime = ROOT / '.test-runtime'
runtime.mkdir(exist_ok=True)
count = 0
for directory in ('inference', 'utils', 'training', 'rl_engine', 'demo', 'tests'):
    for source in (AI / directory).rglob('*.py'):
        ast.parse(source.read_text(encoding='utf-8-sig'), filename=str(source)); count += 1
for source in (ROOT / 'honeypot').rglob('*.py'):
    ast.parse(source.read_text(encoding='utf-8-sig'), filename=str(source)); count += 1
print('Python syntax files:', count, flush=True)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
env = dict(os.environ, SENTINEL_KEY=secrets.token_hex(32), MODEL_DIR=str(AI / 'models'),
           Q_TABLE_PATH=str(runtime / 'smoke-q-table.json'), SENTINEL_API='http://127.0.0.1:1/api')
log = (runtime / 'native-ai.log').open('w')
proc = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'inference.main:app', '--host', '127.0.0.1', '--port', str(port)],
                        cwd=AI, env=env, stdout=log, stderr=subprocess.STDOUT)
try:
    with httpx.Client(base_url=f'http://127.0.0.1:{port}', timeout=15) as client:
        for attempt in range(60):
            try:
                if client.get('/ready').status_code == 200: break
            except httpx.HTTPError: pass
            if proc.poll() is not None: raise RuntimeError('AI process exited; inspect native-ai.log')
            time.sleep(.5)
        else: raise RuntimeError('AI readiness timed out')
        headers = {'X-API-Key': env['SENTINEL_KEY']}
        assert client.post('/predict/eval', json={}).status_code == 401
        before = client.get('/model/stats', headers=headers).json()
        results = []
        for name in ('Monday-WorkingHours.pcap_ISCX.csv', 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'):
            frame = None
            expected_label = 'DDoS' if name.startswith('Friday') else 'BENIGN'
            for chunk in pd.read_csv(AI / 'datasets' / 'cicids2017' / name, chunksize=10000):
                label_column = next(c for c in chunk.columns if c.strip().lower() == 'label')
                matching = chunk[chunk[label_column].astype(str).str.strip() == expected_label]
                if not matching.empty:
                    frame = matching.head(1)
                    break
            assert frame is not None, 'Expected dataset label not found'
            features, _ = prepare_features(frame)
            record = dict(zip(FEATURE_NAMES, features[0].tolist()))
            record.update(sourceIP='192.0.2.1', timestamp='2026-10-13T12:00:00+05:30')
            response = client.post('/predict/eval', headers=headers, json=record)
            response.raise_for_status()
            result = response.json()['result']
            assert 'featureVector' not in result
            results.append({'datasetLabel': expected_label, **{key: result[key] for key in ('predictedClass','threatScore','action','modelVersion')}})
        assert client.get('/model/stats', headers=headers).json() == before
        report = {'nativeHTTP': 'passed', 'syntaxFiles': count, 'unauthenticatedRequest': 401,
                  'datasetRows': results, 'evaluationSideEffects': 'none'}
        (runtime / 'native-ai-result.json').write_text(json.dumps(report, indent=2))
        print(json.dumps(report), flush=True)
finally:
    proc.terminate()
    try: proc.wait(timeout=10)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    log.close()
