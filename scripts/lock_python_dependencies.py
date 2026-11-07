"""Attach all published PyPI SHA-256 hashes to a pip-compile resolved dependency set.

Usage: python scripts/lock_python_dependencies.py resolved.txt node-manager/requirements.lock
Resolution is a separate pip-compile step; this script never selects versions or installs packages.
"""
import concurrent.futures
import json
from pathlib import Path
import re
import sys
import urllib.request


def hashed(requirement):
    match=re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)(\s*;.*)?",requirement)
    if not match:
        raise ValueError("Expected a fully pinned requirement: "+requirement)
    name,version,_=match.groups()
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json",timeout=30) as response:
        release=json.load(response)
    hashes=sorted({item['digests']['sha256'] for item in release['urls'] if not item.get('yanked')})
    if not hashes or not all(re.fullmatch(r'[a-f0-9]{64}',value) for value in hashes):
        raise ValueError("Missing release hashes: "+name)
    return requirement+" \\\n"+" \\\n".join("    --hash=sha256:"+value for value in hashes)


if __name__=='__main__':
    source,target=map(Path,sys.argv[1:])
    requirements=[line.strip() for line in source.read_text(encoding='utf-8').splitlines() if line.strip() and not line.lstrip().startswith('#')]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        blocks=list(pool.map(hashed,requirements))
    target.write_text("# Resolved with pip-compile on Python 3.12; PyPI release hashes attached by scripts/lock_python_dependencies.py.\n# Install: python -m pip install --only-binary=:all: --require-hashes -r requirements.lock\n\n"+"\n\n".join(blocks)+"\n",encoding='utf-8')
