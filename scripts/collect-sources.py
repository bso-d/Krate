#!/usr/bin/env python3
"""Collect the corresponding source for every copyleft component of the container images
an offline package redistributes.

Usage:
  scripts/collect-sources.py --edition kraft --lock dist/release/package-kraft-v9/krate-kraft-v9-arm64.tar.gz.images.lock.tsv \
      --out dist/sources [--archive dist/release/.../krate-kraft-v9-arm64-sources.tar]
  scripts/collect-sources.py --edition epc --templates --arch amd64 --out dist/sources
  scripts/collect-sources.py --edition kraft --package-dir dist/release/package-kraft-v9 --out dist/sources

For every image (and, with --platforms both, for both linux/amd64 and linux/arm64) the
image filesystem is read offline (docker create + docker export, never run), its
components and licences are inventoried, copyleft components are selected and their
exact-version source is downloaded from the authoritative origin and hash-verified.
Anything that cannot be obtained is listed as UNRESOLVED with its reason; nothing is
skipped silently. Output: <out>/<edition>/ with sources/, by-image/, manifest.json and
SOURCES.md, and optionally a tar archive split into parts below GitHub's 2 GiB limit.
See LICENSE-SOURCES.md."""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import faulthandler
import signal
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent / 'source-handlers'))

import alpine  # noqa: E402
import busybox  # noqa: E402
import debian  # noqa: E402
import golang  # noqa: E402
import image_scan  # noqa: E402
import jdk  # noqa: E402
import maven  # noqa: E402
import npm  # noqa: E402
import pypi  # noqa: E402
import rpm  # noqa: E402
from common import (Cache, Component, SourceFile, Unresolved, VerificationError, log, place,  # noqa: E402
                    sha256_file, slug)

SCHEMA = 'krate-corresponding-source/1'
GITHUB_ASSET_LIMIT = 2 * 1024 ** 3
DEFAULT_PART = 2000 * 1024 ** 2
TEMPLATES = {
    'kraft': ['kraft/.env.template', 'monitoring/.env.template'],
    'epc': ['epc/.env.template', 'monitoring/.env.template'],
    'zk': ['zk/.env.template', 'zk/monitoring/.env.template'],
}
KAFBAT_DOCKERFILE = ROOT / 'kafbat-ui' / 'Dockerfile'
HANDLER_ORDER = [debian, alpine, rpm, busybox, jdk, golang, maven, pypi, npm]


# ---------------------------------------------------------------- inputs

def images_from_lock(path):
    rows = []
    lines = Path(path).read_text().splitlines()
    header = lines[0].split('\t')
    for line in lines[1:]:
        if not line.strip():
            continue
        row = dict(zip(header, line.split('\t')))
        rows.append({'ref': row['source_reference'], 'image_id': row.get('image_id') or None,
                     'repo_digests': json.loads(row.get('repo_digests') or '[]'),
                     'arch': (row.get('platform') or 'linux/amd64').split('/')[1],
                     'archive_sha256': row.get('archive_sha256'), 'input': str(path)})
    return rows


def images_from_templates(edition, arch):
    rows = []
    for t in TEMPLATES[edition]:
        for line in (ROOT / t).read_text().splitlines():
            m = re.match(r'^([A-Z0-9_]+_IMAGE)=(\S+)$', line)
            if m:
                rows.append({'ref': m.group(2), 'image_id': None, 'repo_digests': [], 'arch': arch,
                             'input': t})
    return rows


def dedupe(rows):
    seen, out = set(), []
    for r in rows:
        k = (r['ref'], r['arch'])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def candidates(row):
    c = []
    if row.get('image_id'):
        c.append(row['image_id'])
    name = row['ref'].split('@', 1)[0].rsplit(':', 1)[0]
    for d in row.get('repo_digests') or []:
        if d.split('@', 1)[0] == name:
            c.append(d)
    c += [d for d in row.get('repo_digests') or [] if d not in c]
    c.append(row['ref'])
    return c


def kafbat_base():
    m = re.search(r'^ARG KAFBAT_BASE_IMAGE=(\S+)', KAFBAT_DOCKERFILE.read_text(), re.M)
    return m.group(1) if m else None


# ---------------------------------------------------------------- distro

def describe_distro(facts):
    osr = {}
    for text in (facts.get('os_release') or {}).values():
        for line in text.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                osr[k] = v.strip('"')
    if facts.get('apk_installed'):
        kind = 'apk'
    elif facts.get('dpkg_status'):
        kind = 'dpkg'
    elif facts.get('dpkg_status_d'):
        kind = 'dpkg status.d (distroless)'
    elif facts.get('rpmdb_dir'):
        kind = 'rpm'
    else:
        kind = 'none'
    if osr:
        name = osr.get('PRETTY_NAME') or osr.get('NAME', '')
        if name == 'Distroless':
            name = f'Distroless ({osr.get("NAME", "")} {osr.get("VERSION_ID", "")})'.strip()
        return {'distro': name, 'id': osr.get('ID'), 'version_id': osr.get('VERSION_ID'), 'packages': kind}
    if facts.get('busybox'):
        bb = next(iter(facts['busybox'].values()))
        return {'distro': f'BusyBox {bb.get("version")} static ({bb.get("libc")}) base, no package database',
                'id': 'busybox', 'version_id': bb.get('version'), 'packages': kind}
    return {'distro': 'unknown (no os-release, no package database)', 'id': None, 'version_id': None,
            'packages': kind}


def is_copyleft_glibc_static(facts):
    return facts.get('_static_glibc') or []


def register_static_glibc(facts, image_ref, arch, cache, registry):
    """Debian glibc revisions that can have been linked into a static cgo binary."""
    hits = is_copyleft_glibc_static(facts)
    if not hits:
        return
    path, info = hits[0]
    comment = ' '.join(info['elf'].get('comment') or [])
    osr = ' '.join((facts.get('os_release') or {}).values())
    code = re.search(r'VERSION_CODENAME=(\w+)', osr)
    vid = re.search(r'VERSION_ID="?(\d+)', osr)
    names = {'11': 'bullseye', '12': 'bookworm', '13': 'trixie', '14': 'forky'}
    suite = code.group(1) if code else names.get(vid.group(1)) if vid else None
    if 'Debian' not in comment or not suite:
        key = f'glibc-static:{image_ref}'
        comp = registry.setdefault(key, Component(key=key, ecosystem='glibc', name='glibc (static)',
                                                  version='unknown', licence='LGPL-2.1-or-later',
                                                  category='copyleft', families=['LGPL']))
        comp.fetch = {'unresolved': f'{path} statically links glibc but the toolchain ({comment or "no .comment"}) '
                                    'does not identify a distribution glibc build'}
        comp.add_image(image_ref, arch, path)
        return
    mad = cache.cached_json(f'https://api.ftp-master.debian.org/madison?package=glibc&s={suite}&f=json',
                            max_age=86400) or []
    current = None
    for entry in mad:
        for _suite, vers in entry.get('glibc', {}).items():
            current = next(iter(vers))
    if not current:
        raise Unresolved(f'cannot find glibc in Debian {suite}')
    release = current.split('+deb')[0]
    created = (facts.get('created') or '')[:10].replace('-', '')
    listing = cache.cached_json(f'{debian.SNAPSHOT}/mr/package/glibc/', max_age=86400)
    versions = [r['version'] for r in listing['result']
                if r['version'] == release or r['version'].startswith(release + '+deb')]
    for ver in sorted(versions):
        files = debian.srcfiles(cache, 'glibc', ver)
        first = min(f['first_seen'] for f in files if f['name'].endswith('.dsc'))
        if first[:8] > created:
            continue
        key = f'debian:glibc@{ver}'
        comp = registry.get(key)
        if comp is None:
            comp = Component(key=key, ecosystem='debian', name='glibc', version=ver,
                             licence='LGPL-2.1-or-later (and others, see debian/copyright)',
                             category='copyleft', families=['LGPL'])
            registry[key] = comp
        note = (f'{path} is a static cgo binary built with {comment.split("clang")[0].strip()}; the exact '
                f'Debian glibc revision is not recorded in the binary, so every Debian {suite} glibc '
                f'revision published before the image was built ({facts.get("created", "")[:10]}) is shipped')
        if note not in comp.notes:
            comp.notes.append(note)
        comp.add_image(image_ref, arch, f'{path} (static glibc, LGPL-2.1 section 6 relinking)')


# ---------------------------------------------------------------- fetching

def handler_for(comp):
    if comp.key.startswith(('debian-file:', 'glibc-static:')):
        return None
    return {'debian': debian, 'alpine': alpine, 'rpm': rpm, 'maven': maven, 'jar': maven,
            'go': golang, 'git': golang, 'jdk': jdk, 'busybox': busybox, 'pypi': pypi,
            'npm': npm}.get(comp.ecosystem)


def fetch_component(comp, cache, out_dir, workroot):
    h = handler_for(comp)
    if h is None:
        raise Unresolved(comp.fetch.get('unmatched') or comp.fetch.get('unresolved') or 'no handler')
    if h in (golang, jdk, busybox, npm):
        return h.fetch(comp, cache, out_dir, 'sources', workroot)
    return h.fetch(comp, cache, out_dir, 'sources')


def run_fetches(comps, cache, out_dir, workroot, jobs):
    serial = [c for c in comps if c.ecosystem in ('git', 'busybox', 'jdk')]
    parallel = [c for c in comps if c not in serial]
    lock = threading.Lock()
    done = [0]

    def one(comp):
        try:
            files = fetch_component(comp, cache, out_dir, workroot)
            recs = []
            for src, rel, origin, how in files:
                place(src, out_dir / rel)
                recs.append(SourceFile(path=rel, sha256=sha256_file(out_dir / rel), size=(out_dir / rel).stat().st_size,
                                       origin=origin, verification=how))
            comp.files = recs
            comp.status = 'resolved'
        except (Unresolved, VerificationError) as exc:
            comp.status = 'unresolved'
            kind = 'hash verification failed: ' if isinstance(exc, VerificationError) else ''
            comp.reason = kind + str(exc)
        except Exception as exc:  # report, never skip silently
            comp.status = 'unresolved'
            comp.reason = f'{type(exc).__name__}: {exc}'
        with lock:
            done[0] += 1
            if done[0] % 25 == 0 or comp.status == 'unresolved':
                log(f'[{done[0]}/{len(comps)}] {comp.key}: {comp.status} {comp.reason[:160]}')

    for c in serial:
        one(c)
    with cf.ThreadPoolExecutor(max_workers=jobs) as pool:
        list(pool.map(one, parallel))


# ---------------------------------------------------------------- output

def write_by_image(out_dir, images, registry):
    by = out_dir / 'by-image'
    if by.exists():
        shutil.rmtree(by)
    for img in images:
        d = by / slug(img['ref'].split('@', 1)[0].replace('/', '__'))
        for key in img['components']:
            comp = registry[key]
            for f in comp.files:
                link = d / slug(comp.ecosystem + '_' + comp.name + '_' + comp.version) / Path(f.path).name
                if link.exists() or link.is_symlink():
                    continue
                link.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(os.path.relpath(out_dir / f.path, link.parent), link)


def human_size(n):
    for unit in ('B', 'KiB', 'MiB', 'GiB'):
        if n < 1024 or unit == 'GiB':
            return f'{n:.1f} {unit}' if unit != 'B' else f'{n} B'
        n /= 1024


def write_sources_md(out_dir, manifest):
    m = manifest
    lines = [f'# Corresponding source: {m["edition"]} offline package', '',
             f'Generated {m["generated"]} by `scripts/collect-sources.py` (schema `{m["schema"]}`).', '',
             'This archive holds the corresponding source for the copyleft components (GPL, LGPL, AGPL, '
             'MPL, EPL, CDDL and similar) in the container images that the offline package '
             'redistributes. `manifest.json` is the machine-readable record: every file with its '
             'SHA-256, origin URL and how it was verified. `sources/` holds the files once; '
             '`by-image/` links them per image. See LICENSE-SOURCES.md in the Krate repository.', '',
             '## Totals', '',
             f'- Images: {len(m["images"])} image/platform pairs from {", ".join(m["inputs"])}',
             f'- Copyleft components resolved: {m["totals"]["resolved"]}',
             f'- UNRESOLVED: {m["totals"]["unresolved"]}',
             f'- Source files: {m["totals"]["files"]}, {human_size(m["totals"]["bytes"])} ({m["totals"]["bytes"]} bytes)', '',
             '## Images', '',
             '| Image | Platform | Distribution / packages | Copyleft components | Source bytes |',
             '|---|---|---|---|---|']
    for img in m['images']:
        lines.append(f'| `{img["ref"].split("@")[0]}` | {img["arch"]} | {img["distro"]["distro"]} '
                     f'({img["distro"]["packages"]}) | {img["copyleft_components"]} '
                     f'({img["unresolved_components"]} unresolved) | {human_size(img["source_bytes"])} |')
    unresolved = [c for c in m['components'] if c['status'] == 'unresolved']
    lines += ['', '## UNRESOLVED', '']
    if not unresolved:
        lines.append('None.')
    for c in unresolved:
        imgs = ', '.join(f'`{k.split("@")[0]}` ({"/".join(v)})' for k, v in c['images'].items())
        lines.append(f'- **{c["key"]}** ({c["licence"][:120]}) in {imgs}: {c["reason"]}')
    lines += ['', '## Components with source', '',
              '| Component | Version | Licence | Files | Verification |', '|---|---|---|---|---|']
    for c in m['components']:
        if c['status'] != 'resolved':
            continue
        files = '<br>'.join(f'`{f["path"].split("/", 1)[1]}`' for f in c['files'][:6])
        if len(c['files']) > 6:
            files += f'<br>... {len(c["files"]) - 6} more'
        how = c['files'][0]['verification'] if c['files'] else ''
        lines.append(f'| {c["ecosystem"]}: `{c["name"]}` | {c["version"]} | {c["licence"][:100]} | {files} | {how[:120]} |')
    elected = [c for c in m['components'] if c['category'] == 'elected-permissive']
    lines += ['', '## Dual-licensed components shipped under the permissive option', '']
    for c in elected:
        lines.append(f'- {c["ecosystem"]}: `{c["name"]}` {c["version"]}: {c["licence"][:160]}')
    if not elected:
        lines.append('None.')
    lines += ['', '## Verifying and rebuilding', '',
              '```bash', 'cd <extracted directory>',
              "python3 -c 'import json,hashlib;m=json.load(open(\"manifest.json\"));"
              "bad=[f[\"path\"] for c in m[\"components\"] for f in c[\"files\"] "
              "if hashlib.sha256(open(f[\"path\"],\"rb\").read()).hexdigest()!=f[\"sha256\"]];print(bad or \"all files OK\")'",
              '```', '',
              'Debian sources: `dpkg-source -x <name>_<version>.dsc`. Alpine: the `aports/` directory is '
              'the APKBUILD at the build commit; put `distfiles/` next to it and run `abuild -r`. RPM: '
              '`rpmbuild --rebuild <name>.src.rpm`. Maven: the `-sources.jar` and POM of the exact version. '
              'Go: module zips as served by proxy.golang.org (usable as a GOPROXY file tree). '
              'git: complete tree of the recorded commit.', '']
    (out_dir / 'SOURCES.md').write_text('\n'.join(lines))


def make_archive(out_dir, archive: Path, part_size):
    archive.parent.mkdir(parents=True, exist_ok=True)
    tmp = archive.with_suffix(archive.suffix + '.tmp')
    base = archive.name.removesuffix('.tar')
    entries = sorted(p for p in out_dir.rglob('*'))
    with tarfile.open(tmp, 'w', format=tarfile.PAX_FORMAT) as tar:
        tar.add(out_dir, arcname=base, recursive=False, filter=_norm)
        for p in entries:
            tar.add(p, arcname=f'{base}/{p.relative_to(out_dir)}', recursive=False, filter=_norm)
    os.replace(tmp, archive)
    for old in archive.parent.glob(archive.name + '.part*'):
        old.unlink()
    whole = sha256_file(archive)
    size = archive.stat().st_size
    lines = [f'{whole}  {archive.name}']
    parts = []
    if size >= GITHUB_ASSET_LIMIT or size > part_size:
        with open(archive, 'rb') as fh:
            i = 0
            while True:
                chunk_path = archive.parent / f'{archive.name}.part{i:03d}'
                written = 0
                h = hashlib.sha256()
                with open(chunk_path, 'wb') as out:
                    while written < part_size:
                        block = fh.read(min(1 << 20, part_size - written))
                        if not block:
                            break
                        out.write(block)
                        h.update(block)
                        written += len(block)
                if written == 0:
                    chunk_path.unlink()
                    break
                parts.append(chunk_path)
                lines.append(f'{h.hexdigest()}  {chunk_path.name}')
                i += 1
        archive.unlink()
    (archive.parent / f'{archive.name}.sha256').write_text('\n'.join(lines) + '\n')
    return whole, size, parts


def _norm(info):
    info.uid = info.gid = 0
    info.uname = info.gname = 'root'
    info.mtime = 0
    return info


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--edition', required=True, choices=sorted(TEMPLATES))
    ap.add_argument('--lock', action='append', default=[], help='images.lock.tsv (repeatable)')
    ap.add_argument('--package-dir', help='directory holding *.images.lock.tsv files')
    ap.add_argument('--templates', action='store_true', help='read images from the edition .env.templates')
    ap.add_argument('--arch', default='amd64', choices=['amd64', 'arm64'], help='platform for --templates')
    ap.add_argument('--platforms', default='both', choices=['both', 'input'],
                    help='inventory both linux/amd64 and linux/arm64 of registry images (default) or only the input platform')
    ap.add_argument('--out', default=str(ROOT / 'dist' / 'sources'))
    ap.add_argument('--cache', default=str(ROOT / 'dist' / 'sources-cache'))
    ap.add_argument('--archive', help='write a tar of the edition directory (split into parts if needed)')
    ap.add_argument('--part-size', type=int, default=DEFAULT_PART, help='bytes per archive part (< 2 GiB)')
    ap.add_argument('--no-pull', action='store_true', help='never pull missing images')
    ap.add_argument('--jobs', type=int, default=6)
    ap.add_argument('--fail-on-unresolved', action='store_true')
    args = ap.parse_args(argv)
    faulthandler.register(signal.SIGUSR1)  # `kill -USR1 <pid>` prints where a run is waiting
    if args.part_size >= GITHUB_ASSET_LIMIT:
        ap.error('--part-size must be below 2 GiB')

    rows = []
    locks = list(args.lock)
    if args.package_dir:
        locks += sorted(str(p) for p in Path(args.package_dir).glob('*.images.lock.tsv'))
    for lock in locks:
        rows += images_from_lock(lock)
    if args.templates:
        rows += images_from_templates(args.edition, args.arch)
    if not rows:
        ap.error('give --lock, --package-dir or --templates')
    rows = dedupe(rows)

    cache = Cache(Path(args.cache))
    workroot = Path(args.cache) / 'work'
    workroot.mkdir(parents=True, exist_ok=True)
    out_dir = Path(args.out) / args.edition
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    registry: dict[str, Component] = {}
    images = []
    for row in rows:
        arches = [row['arch']]
        local_only = row['ref'].startswith('krate/') or not re.search(r'@sha256:', row['ref'])
        if args.platforms == 'both' and not local_only:
            arches.append('arm64' if row['arch'] == 'amd64' else 'amd64')
        for arch in arches:
            expected = row['image_id'] if arch == row['arch'] else None
            notes = []
            facts = image_scan.inventory(candidates(row) if arch == row['arch'] else [row['ref']], arch,
                                         Path(args.cache), workroot, pull=not args.no_pull, expected_id=expected)
            if facts and expected and facts['image_id'] != expected:
                notes.append(f'resolved image id {facts["image_id"]} differs from the lock file {expected}')
            if facts is None and row['ref'].startswith('krate/kafka-ui') and kafbat_base():
                base = kafbat_base()
                notes.append(f'{row["ref"]} is a locally built image that is not present; its base {base} '
                             '(kafbat-ui/Dockerfile) was inventoried instead. The Krate layer adds only the '
                             'patched Kafbat api.jar (Apache-2.0 Kafbat plus the patches in kafbat-ui/) and notices.')
                facts = image_scan.inventory([base], arch, Path(args.cache), workroot, pull=not args.no_pull)
                if facts:
                    # The Krate image would carry the labels kafbat-ui/Dockerfile sets.
                    facts['labels'] = {**(facts.get('labels') or {}),
                                       **dict(re.findall(r'(io\.krate\.[\w.-]+)="([^"]+)"', KAFBAT_DOCKERFILE.read_text()))}
            entry = {'ref': row['ref'], 'arch': arch, 'input': row['input'], 'role': 'packaged' if arch == row['arch']
                     else 'other-platform (same index)', 'notes': notes}
            if facts is None:
                entry.update({'image_id': None, 'distro': describe_distro({}), 'components': []})
                key = f'image-missing:{row["ref"]}@{arch}'
                comp = Component(key=key, ecosystem='image', name=row['ref'], version=arch,
                                 licence='unknown (image not available)', category='unknown', families=[])
                comp.fetch = {'unresolved': f'image {row["ref"]} for linux/{arch} is not available locally '
                                            'and could not be pulled; its components were not inventoried'}
                comp.add_image(row['ref'], arch)
                registry[key] = comp
                entry['components'].append(key)
                images.append(entry)
                log(f'UNRESOLVED image {row["ref"]} {arch}')
                continue
            before = set(registry)
            for h in HANDLER_ORDER:
                try:
                    h.components(facts, row['ref'], arch, cache, registry)
                except (Unresolved, VerificationError) as exc:
                    key = f'inventory-error:{h.__name__}:{row["ref"]}@{arch}'
                    comp = Component(key=key, ecosystem='inventory', name=h.__name__, version=arch,
                                     licence='unknown', category='unknown', families=[])
                    comp.fetch = {'unresolved': f'{h.__name__} inventory failed: {exc}'}
                    comp.add_image(row['ref'], arch)
                    registry[key] = comp
            register_static_glibc(facts, row['ref'], arch, cache, registry)
            entry.update({'image_id': facts['image_id'], 'distro': describe_distro(facts),
                          'created': facts.get('created'), 'components': []})
            images.append(entry)
            log(f'inventoried {row["ref"]} {arch}: {len(set(registry) - before)} new components')

    log('classifying licences')
    npm.classify(registry, cache)
    comps = list(registry.values())
    maven.classify(comps, cache)
    golang.classify(comps, cache, workroot)
    need = [c for c in comps if c.needs_source() or c.ecosystem in ('image', 'inventory')]
    for c in comps:
        if c not in need:
            c.status = 'not-required'
            c.reason = ('dual licence: permissive option elected' if c.category == 'elected-permissive'
                        else 'no copyleft licence')
    for c in need:
        if c.category == 'unknown' and c.ecosystem not in ('image', 'inventory'):
            c.notes.append('licence could not be classified; source collected conservatively')
    alpine.prepare([c for c in need if c.ecosystem == 'alpine'], cache, workroot)
    log(f'fetching sources for {len(need)} components ({len(comps)} inventoried)')
    run_fetches(need, cache, out_dir, workroot, args.jobs)

    # Manifest
    by_key = {c.key: c for c in comps}
    for img in images:
        img['components'] = sorted(k for k, c in by_key.items()
                                   if img['ref'] in c.images and img['arch'] in c.images[img['ref']])
    image_rows = []
    for img in images:
        keys = img['components']
        sel = [by_key[k] for k in keys if by_key[k].status in ('resolved', 'unresolved')]
        image_rows.append({**{k: v for k, v in img.items() if k != 'components'},
                           'components': keys,
                           'copyleft_components': len(sel),
                           'unresolved_components': sum(c.status == 'unresolved' for c in sel),
                           'source_bytes': sum(f.size for c in sel for f in c.files)})
    seen, total_bytes, total_files = set(), 0, 0
    for c in comps:
        for f in c.files:
            if f.path not in seen:
                seen.add(f.path)
                total_bytes += f.size
                total_files += 1
    manifest = {
        'schema': SCHEMA, 'edition': args.edition,
        # SOURCE_DATE_EPOCH makes the manifest (and so the archive) reproducible.
        'generated': (dt.datetime.fromtimestamp(int(os.environ['SOURCE_DATE_EPOCH']), dt.timezone.utc)
                      if os.environ.get('SOURCE_DATE_EPOCH') else dt.datetime.now(dt.timezone.utc)
                      ).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'inputs': [str(Path(p).name) for p in locks] + (TEMPLATES[args.edition] if args.templates else []),
        'policy': ('Source is shipped for every component under a copyleft licence (GPL, LGPL, AGPL, MPL, EPL, '
                   'CDDL, EUPL, OSL, Sleepycat and similar) and for components whose licence could not be '
                   'classified. Disjunctive licences with a permissive option are listed as elected-permissive. '
                   'Components that list several licences without saying "or" are treated as copyleft.'),
        'images': image_rows,
        'components': [c.asdict() for c in sorted(comps, key=lambda c: c.key)],
        'totals': {'inventoried': len(comps), 'resolved': sum(c.status == 'resolved' for c in comps),
                   'unresolved': sum(c.status == 'unresolved' for c in comps),
                   'not_required': sum(c.status == 'not-required' for c in comps),
                   'files': total_files, 'bytes': total_bytes},
    }
    (out_dir / 'manifest.json').write_text(json.dumps(manifest, indent=1, sort_keys=False) + '\n')
    write_by_image(out_dir, images, by_key)
    write_sources_md(out_dir, manifest)
    log(f'{args.edition}: {manifest["totals"]}')
    if args.archive:
        whole, size, parts = make_archive(out_dir, Path(args.archive), args.part_size)
        log(f'archive {args.archive}: {size} bytes sha256 {whole}' + (f' in {len(parts)} parts' if parts else ''))
    if args.fail_on_unresolved and manifest['totals']['unresolved']:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
