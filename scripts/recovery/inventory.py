#!/usr/bin/env python3
"""Freeze historical source inventory; report omissions without inferring semantics.
Requires fetched refs/pull/1..41 and git. Output goes to stdout.
"""
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


@lru_cache(maxsize=None)
def git(*args):
    return subprocess.check_output(['git', *args])


def inventory(ref):
    sha = git('rev-parse', ref).decode().strip()
    files = {}
    for record in git('ls-tree', '-rz', sha).split(b'\0'):
        if not record:
            continue
        meta, path = record.split(b'\t', 1)
        _, kind, oid = meta.split()
        if kind != b'blob':
            continue
        name = path.decode()
        content = git('cat-file', 'blob', oid.decode())
        item = {'blob': oid.decode(), 'sha256': hashlib.sha256(content).hexdigest()}
        if name.endswith('.rs'):
            text = content.decode()
            # Lexical index only: retains signatures for review, not a Rust parser.
            item['public_declarations'] = sorted(set(re.findall(
                r'\bpub(?:\([^)]*\))?\s+(?:(?:async|unsafe|const)\s+)*(?:fn|struct|enum|trait|type|mod|const|static)\s+[^;{]+', text)))
            item['test_names'] = sorted(set(re.findall(r'#\[test\]\s*fn\s+(\w+)', text)))
        files[name] = item
    return {'commit': sha, 'tree': git('rev-parse', sha+'^{tree}').decode().strip(), 'files': files}


def main():
    target = inventory(sys.argv[1] if len(sys.argv) > 1 else 'HEAD')
    frozen = json.loads((Path(__file__).resolve().parents[2] / 'docs/recovery/HISTORICAL_HEADS.json').read_text())
    sources = {n: inventory(v['commit']) for n, v in frozen.items()}
    missing = {}
    missing_tests = {}
    missing_public_names = {}
    for n, source in sources.items():
        for path, old in source['files'].items():
            if path not in target['files']:
                missing.setdefault(path, []).append(n)
                continue
            new = target['files'][path]
            for test in set(old.get('test_names', [])) - set(new.get('test_names', [])):
                missing_tests.setdefault(path+':'+test, []).append(n)
            # Names and full declarations are both retained in the inventory.
            names = lambda item: {re.search(r'(?:fn|struct|enum|trait|type|mod|const|static)\s+(\w+)', d).group(1) for d in item.get('public_declarations', [])}
            for symbol in names(old) - names(new):
                missing_public_names.setdefault(path+':'+symbol, []).append(n)
    print(json.dumps({'target': target, 'historical': sources,
        'missing_paths': missing, 'missing_test_names': missing_tests,
        'missing_public_names': missing_public_names,
        'limitations': 'Lexical index, not semantic/API compatibility proof. Compare retained full signatures, errors, fixtures and behavioral diffs; a preserved name is insufficient.'}, indent=2, sort_keys=True))
    return bool(missing or missing_tests or missing_public_names)


if __name__ == '__main__':
    sys.exit(main())
