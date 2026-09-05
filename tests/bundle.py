#!/usr/bin/env python3
"""Build and inspect a real offline bundle, including nested image manifests."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import shutil

ROOT = Path(__file__).resolve().parents[1]


def main():
    work = Path(tempfile.mkdtemp(prefix='krate-bundle-test-'))
    try:
        arch = subprocess.check_output(['docker', 'version', '--format', '{{.Server.Arch}}'], text=True).strip()
        make = shutil.which('gmake') or shutil.which('make')
        subprocess.run([make, 'bundle', 'MODE=kraft', 'VERSION=v0', f'ARCH={arch}',
                        'NO_PULL=1', f'DIST_DIR={work}'], cwd=ROOT, check=True)
        bundle = next(work.glob('*.tar.gz'))
        expected = set()
        for path in [ROOT / 'kraft/.env.template', ROOT / 'monitoring/.env.template']:
            for line in path.read_text().splitlines():
                if '_IMAGE=' in line and not line.startswith('#'):
                    expected.add(line.split('=', 1)[1])
        with bundle.open('rb') as stream:
            digest_state = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest_state.update(chunk)
            digest = digest_state.hexdigest()
        assert bundle.with_suffix(bundle.suffix + '.sha256').read_text().split()[0] == digest
        found = set()
        with tarfile.open(bundle) as outer:
            names = outer.getnames()
            assert not any(n.endswith('/.env') for n in names)
            assert any(n.endswith('/monitoring/seed-alerting.py') for n in names)
            assert any(n.endswith('/monitoring/prometheus/alerts.yml') for n in names)
            for member in outer.getmembers():
                if not member.name.endswith('.tar'):
                    continue
                # Seekable temp file avoids retaining large image layers in RAM.
                with tempfile.TemporaryFile() as image:
                    shutil.copyfileobj(outer.extractfile(member), image)
                    image.seek(0)
                    with tarfile.open(fileobj=image) as inner:
                        manifest = json.load(inner.extractfile('manifest.json'))
                        for entry in manifest:
                            found.update(entry.get('RepoTags') or [])
                            config = json.load(inner.extractfile(entry['Config']))
                            assert config['architecture'] == arch, member.name
        assert expected == found, (expected - found, found - expected)
        print(f'PASS: real bundle checksum, no .env, monitoring config, all {len(found)} images, architecture {arch}')
    finally:
        shutil.rmtree(work)


if __name__ == '__main__':
    main()
