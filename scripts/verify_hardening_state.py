"""Read only preserved assets and application source; skip all runtime databases/profiles."""
import concurrent.futures
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT.parent / 'sentinelai-before-auth-20261014-94439a22'
SKIP = {'.test-runtime', '.venv', 'node_modules', 'dist', 'logs', '__pycache__',
        '.pytest_cache', '.git', '.agents', '.codex', 'runtime'}


def digest(path):
    if path.name.lower() == 'cache.db':
        raise ValueError('Prohibited file')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    preserved = json.loads((ROOT / 'docs/PRESERVED_ASSETS_SHA256.json').read_text())
    def verify(asset):
        return asset['path'] if digest(ROOT / asset['path']) != asset['sha256'].lower() else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        mismatches = [value for value in pool.map(verify, preserved) if value]
    verification = json.loads((BACKUP / 'BACKUP_VERIFICATION.json').read_text())
    baseline = {item['path'].replace('\\', '/'): item['sha256'] for item in verification['manifest']}
    changes = []
    paths = set()
    for current, directories, files in os.walk(ROOT):
        directories[:] = [name for name in directories if name not in SKIP and not Path(current, name).is_symlink()]
        for name in files:
            path = Path(current, name)
            if name.lower() == 'cache.db' or path.is_symlink():
                continue
            relative = path.relative_to(ROOT).as_posix()
            paths.add(relative)
            actual = digest(path)
            if baseline.get(relative) != actual:
                changes.append({'path': relative, 'status': 'modified' if relative in baseline else 'added', 'sha256': actual})
    for relative in baseline:
        if any(part in SKIP for part in relative.split('/')) or relative.lower().endswith('/cache.db'):
            continue
        if relative not in paths:
            changes.append({'path': relative, 'status': 'removed'})
    evidence = {
        'backup': str(BACKUP), 'backup_verified': verification['verified'],
        'backup_files': verification['files'], 'backup_bytes': verification['bytes'],
        'preserved_asset_count': len(preserved), 'preserved_asset_mismatches': mismatches,
        'changed_files': sorted(changes, key=lambda item: item['path']),
        'unchanged_legacy_lint_helper': digest(ROOT / 'backend/tests/verifyBlocker.js') == baseline['backend/tests/verifyBlocker.js'],
    }
    (ROOT / '.test-runtime/hardening-state-verification.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({key: value for key, value in evidence.items() if key != 'changed_files'}))
    if '--list' in sys.argv:
        print(json.dumps(changes, indent=2))
    if mismatches:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
