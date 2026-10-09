#!/usr/bin/env python3
"""Fail a package build if any Compose image or required SSO file is missing."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    root = args.directory.resolve()
    with (root / 'images.lock.tsv').open() as stream:
        rows = list(csv.DictReader(stream, delimiter='\t'))
    images = {row['runtime_reference'] for row in rows}
    for row in rows:
        archive = root / row['archive']
        if not archive.is_file() or not archive.stat().st_size:
            raise SystemExit('Missing saved image archive')
    manifests = [root / 'docker-compose.yml', root / 'monitoring/docker-compose.yml']
    for manifest in manifests:
        if not manifest.exists():
            continue
        cmd = ['docker', 'compose', '--env-file', str(manifest.parent / '.env.template'),
               '-f', str(manifest), '--profile', '*', 'config', '--images']
        required = set(subprocess.check_output(cmd, text=True).splitlines())
        if required - images:
            raise SystemExit('Compose images missing from package: ' + ', '.join(sorted(required - images)))
    for name in ('sso/configure-dual.py', 'sso/configure.py', 'sso/activate.sh',
                 'sso/preflight.py', 'sso/probe.py', 'auth/ui/local.yml', 'docs/dual-login.md'):
        if not (root / name).is_file():
            raise SystemExit('Missing authentication package file: ' + name)
    monitor_template = root / 'monitoring/.env.template'
    if monitor_template.is_file() and 'FLUENT_BIT_IMAGE=' in monitor_template.read_text():
        for name in ('fluent-bit.conf', 'parsers-multiline.conf', 'metadata.lua', 'discovery.py', 'vendor/dkjson.lua',
                     'vendor/FLUENT-BIT-LICENSE', 'vendor/image-notices/inventory.json',
                     'vendor/image-notices/upstream/inventory.json',
                     'vendor/discovery-notices/inventory.json', 'README.md'):
            if not (root / 'monitoring/fluent-bit' / name).is_file():
                raise SystemExit('Missing monitoring package file: fluent-bit/' + name)
        if not (root / 'monitoring/README.md').is_file():
            raise SystemExit('Missing monitoring package file: README.md')
        notices = root / 'monitoring/fluent-bit/vendor/image-notices'
        for directory in (notices, notices / 'upstream', notices.parent / 'discovery-notices'):
            inventory = json.loads((directory / 'inventory.json').read_text())
            rows = inventory if isinstance(inventory, list) else inventory['copyrights'] + inventory['common_licenses']
            for row in rows:
                file = directory / row['file']
                if file.parent != directory or not file.is_file():
                    raise SystemExit('Missing monitoring package file: ' + row['file'])
                if hashlib.sha256(file.read_bytes()).hexdigest() != row['sha256']:
                    raise SystemExit('Monitoring notice checksum mismatch: ' + row['file'])
    bytecode = sorted(str(path.relative_to(root)) for pattern in ('__pycache__', '*.pyc') for path in root.rglob(pattern))
    if bytecode:
        raise SystemExit('Python bytecode must not ship in release packages: ' + ', '.join(bytecode))
    if (root / '.env').exists() or (root / 'auth/ui/runtime.yml').exists() or (root / 'auth/keycloak/krate-realm.json').exists():
        raise SystemExit('Site configuration must not ship in release packages')
    print(f'Package coverage verified: {len(images)} images, including all optional profiles and SSO helpers.')


if __name__ == '__main__':
    main()
