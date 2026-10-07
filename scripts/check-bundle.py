#!/usr/bin/env python3
"""Fail a package build if any Compose image or required SSO file is missing."""
import argparse
import csv
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
    if (root / '.env').exists() or (root / 'auth/ui/runtime.yml').exists() or (root / 'auth/keycloak/krate-realm.json').exists():
        raise SystemExit('Site configuration must not ship in release packages')
    print(f'Package coverage verified: {len(images)} images, including all optional profiles and SSO helpers.')


if __name__ == '__main__':
    main()
