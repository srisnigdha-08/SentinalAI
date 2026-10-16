"""Verify protected application assets and this task's source backup. No runtime traversal."""
import hashlib
import json
import os
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / '.test-runtime/master-source-backup-20261014-80f776da'
arguments = argparse.ArgumentParser()
arguments.add_argument('--output-name', default='final-state-reviewed.json')
options = arguments.parse_args()
if Path(options.output_name).name != options.output_name or not options.output_name.endswith('.json'):
    raise ValueError('Output must be a JSON basename in the owned evidence directory')
OUTPUT = ROOT / '.test-runtime/master-native-20261014-80f776da' / options.output_name
SKIP = {'.test-runtime', 'node_modules', '.venv', 'dist', 'logs', '__pycache__',
        '.pytest_cache', '.git', '.agents', '.codex', 'datasets', 'data', '.native-integration'}
SUFFIXES = {'.js', '.jsx', '.cjs', '.mjs', '.py', '.md', '.json', '.html', '.css', '.yaml', '.yml', '.txt'}


def redirected(path):
    return bool(path.lstat().st_file_attributes & 0x400)


def digest(path):
    if path.name.lower() == 'cache.db':
        raise ValueError('Prohibited file')
    for parent in (path, *path.parents):
        if redirected(parent):
            raise ValueError('Redirected asset/source path')
        if parent == ROOT:
            break
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


assets = json.loads((ROOT / 'docs/PRESERVED_ASSETS_SHA256.json').read_text())
mismatches = [asset['path'] for asset in assets if digest(ROOT / asset['path']) != asset['sha256'].lower()]
manifest = json.loads((BACKUP / 'BACKUP_VERIFICATION.json').read_text())
backup_mismatches = [entry['path'] for entry in manifest['manifest']
                     if digest(BACKUP / entry['path']) != entry['sha256'].lower()]
baseline = {entry['path'].replace('\\', '/'): entry['sha256'].lower() for entry in manifest['manifest']}
# These existed before the task but were excluded from the selected source snapshot.
# Absence from that snapshot does not prove a file was added by this task.
prior_manifest_path = ROOT.parent / 'sentinelai-before-auth-20261014-94439a22/BACKUP_VERIFICATION.json'
prior_manifest = json.loads(prior_manifest_path.read_text())
prior_hashes = {entry['path'].replace('\\', '/'): entry['sha256'].lower()
                for entry in prior_manifest['manifest']}
excluded_existing_paths = {'models/isolation_forest_cicids_meta.json',
                          'models/rf_classifier_cicids_v2_meta.json', 'paper_text.txt'}
excluded_existing = []
excluded_mismatches = []
for relative in sorted(excluded_existing_paths):
    actual = digest(ROOT / relative)
    matches = prior_hashes.get(relative) == actual
    excluded_existing.append({'path': relative, 'sha256': actual,
                              'matchesPriorApplicationBackupManifest': matches})
    if not matches:
        excluded_mismatches.append(relative)
candidates = set(baseline)
for current, directories, files in os.walk(ROOT):
    directories[:] = [name for name in directories if name not in SKIP and not redirected(Path(current, name))]
    for name in files:
        file = Path(current, name)
        if (name.lower() == 'cache.db' or name.startswith('.env') or redirected(file)
                or file.suffix not in SUFFIXES):
            continue
        candidates.add(file.relative_to(ROOT).as_posix())
changes = []
for relative in sorted(candidates):
    if relative in excluded_existing_paths:
        continue
    file = ROOT / relative
    if not file.exists():
        changes.append({'path': relative, 'status': 'removed'})
        continue
    actual = digest(file)
    if baseline.get(relative) != actual:
        changes.append({'path': relative, 'status': 'modified' if relative in baseline else 'added', 'sha256': actual})
evidence = {'project': str(ROOT), 'gitRepository': (ROOT / '.git').exists(),
            'protectedAssets': len(assets), 'assetMismatches': mismatches,
            'sourceBackup': str(BACKUP), 'backupFiles': manifest['files'],
            'backupBytes': manifest['bytes'], 'backupMismatches': backup_mismatches,
            'changedFiles': changes,
            'inventoryScope': 'Changes since the selected pre-runtime-edit source snapshot',
            'unchangedPreexistingFilesExcludedFromSourceSnapshot': excluded_existing,
            'excludedFileMismatches': excluded_mismatches,
            'priorApplicationBackupManifest': str(prior_manifest_path),
            'supersedesInventoryClassificationOnly': 'final-state.json',
            'skippedRuntimeAndRecoveryResources': True}
with OUTPUT.open('x', encoding='utf-8') as stream:
    json.dump(evidence, stream, indent=2)
print(json.dumps({key: value for key, value in evidence.items() if key != 'changedFiles'}))
raise SystemExit(bool(mismatches or backup_mismatches or excluded_mismatches))
