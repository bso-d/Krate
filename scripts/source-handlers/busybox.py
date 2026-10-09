"""BusyBox binaries that no package manager owns (docker-library `busybox` based images
such as quay.io/prometheus/busybox and distroless :debug), plus the Debian data files
quay.io/prometheus/busybox copies in.

Identification is exact: the BusyBox binary's SHA-256 is searched for in the root
filesystems that docker-library/busybox publishes on its dist-<arch> branches, using the
dist commits that docker-library/official-images recorded around the binary's embedded
build date. The match gives the variant (uclibc/musl/glibc) and the docker-library
source commit. From that commit's Dockerfile.builder:
  * BusyBox tarball, verified against BUSYBOX_SHA256 in the git-pinned Dockerfile;
  * uclibc: Buildroot tarball (SHA-256 from its published .sign file) and uClibc-ng
    (version and SHA-256 from that Buildroot's package/uclibc files);
  * the docker-library/busybox tree at the commit (build configuration and patches)."""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import lzma
import os
import re
import subprocess
import tarfile

from common import Component, Unresolved, VerificationError, http_get, http_json
import debian
import gitsrc

DL_REPO = 'https://github.com/docker-library/busybox'
OI_API = 'https://api.github.com/repos/docker-library/official-images/commits'
OI_RAW = 'https://raw.githubusercontent.com/docker-library/official-images/{c}/library/busybox'
ARCH = {'amd64': 'amd64', 'arm64': 'arm64v8'}


def owned_by_package(facts):
    apk = facts.get('apk_installed') or ''
    if re.search(r'^P:busybox$', apk, re.M):
        return True
    return bool(re.search(r'^Package: busybox', facts.get('dpkg_status') or '', re.M)) or \
        any(k.startswith('busybox') for k in (facts.get('dpkg_status_d') or {}))


def _gh_headers():
    tok = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    return {'Authorization': f'Bearer {tok}'} if tok else {}


def official_images_commits(cache, built):
    t = dt.datetime.strptime(built, '%Y-%m-%d %H:%M:%S').replace(tzinfo=dt.timezone.utc)
    since = (t - dt.timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
    until = (t + dt.timedelta(days=400)).strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f'{OI_API}?path=library/busybox&since={since}&until={until}&per_page=100'
    key = cache.meta_path('oi:' + url)
    if key.exists():
        import json
        return json.loads(key.read_text())
    data = http_json(url, headers=_gh_headers())
    shas = [c['sha'] for c in sorted(data, key=lambda c: c['commit']['committer']['date'])]
    import json
    key.write_text(json.dumps(shas))
    return shas


def _dist_entries(cache, oi_commit, arch):
    text = cache.cached_get(OI_RAW.format(c=oi_commit)).decode()
    src = re.search(r'^GitCommit:\s*([0-9a-f]{40})', text, re.M)
    dist = re.search(rf'^{ARCH[arch]}-GitCommit:\s*([0-9a-f]{{40}})', text, re.M)
    return (src.group(1) if src else None), (dist.group(1) if dist else None)


def _files_with_hash(bare, commit, want):
    """Search the rootfs archives of one dist commit for a file with SHA-256 want."""
    names = subprocess.run(['git', '-C', bare, 'ls-tree', '-r', '--name-only', commit],
                           capture_output=True, text=True, check=True).stdout.splitlines()
    for name in names:
        m = re.match(r'^([^/]+)/(uclibc|musl|glibc)/((?:[^/]+/)?(?:busybox|rootfs)\.tar\.(?:xz|gz))$', name)
        if not m:
            continue
        data = subprocess.run(['git', '-C', bare, 'show', f'{commit}:{name}'], capture_output=True).stdout
        try:
            raw = lzma.decompress(data) if data[:6] == b'\xfd7zXZ\x00' else gzip.decompress(data)
            with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
                for mem in tar:
                    if mem.isfile() and mem.size > 300_000:
                        if hashlib.sha256(tar.extractfile(mem).read()).hexdigest() == want:
                            return m.group(1), m.group(2), name
        except (OSError, lzma.LZMAError, tarfile.TarError, EOFError):
            continue
    return None


def identify(cache, info, arch):
    if not info.get('built'):
        raise Unresolved('BusyBox binary has no build date banner; cannot locate its build')
    bare = gitsrc._bare(cache, DL_REPO)
    tried = []
    for oi in official_images_commits(cache, info['built']):
        src, dist = _dist_entries(cache, oi, arch)
        if not dist or dist in tried:
            continue
        tried.append(dist)
        if not gitsrc.has_commit(bare, dist):
            subprocess.run(['git', '-C', bare, 'fetch', '-q', '--depth', '1', 'origin', dist],
                           capture_output=True, timeout=600)
        if not gitsrc.has_commit(bare, dist):
            continue
        hit = _files_with_hash(bare, dist, info['sha256'])
        if hit:
            return {'source_commit': src, 'dist_commit': dist, 'dir': hit[0], 'variant': hit[1],
                    'archive': hit[2], 'official_images_commit': oi}
    raise Unresolved(f'BusyBox binary sha256 {info["sha256"]} not found in docker-library/busybox '
                     f'dist-{ARCH[arch]} builds recorded by official-images after {info["built"]} '
                     f'(searched {len(tried)} dist commits)')


def components(facts, image_ref, arch, cache, registry):
    if owned_by_package(facts):
        return 0
    n = 0
    seen = set()
    for path, info in sorted((facts.get('busybox') or {}).items()):
        if info['sha256'] in seen:
            continue
        seen.add(info['sha256'])
        key = f'busybox-build:{info["version"]}@{info["sha256"][:16]}'
        comp = registry.get(key)
        if comp is None:
            comp = Component(key=key, ecosystem='busybox', name='busybox (docker-library build)',
                             version=info['version'] or '', licence='GPL-2.0-only',
                             category='copyleft', families=['GPL'])
            comp.fetch = {'info': info, 'arch': arch}
            registry[key] = comp
        comp.add_image(image_ref, arch, f'/{path} sha256 {info["sha256"]} built {info.get("built")} '
                                        f'libc~{info.get("libc")}')
        n += 1
    n += debian_data_files(facts, image_ref, arch, cache, registry)
    return n


def _sign_sha256(text, filename):
    for line in text.splitlines():
        m = re.match(r'^SHA256:\s*([0-9a-f]{64})\s+(\S+)', line.strip())
        if m and m.group(2) == filename:
            return m.group(1)
    return None


def fetch(comp, cache, out_dir, rel_root, workroot):
    info, arch = comp.fetch['info'], comp.fetch['arch']
    found = identify(cache, info, arch)
    bare = gitsrc._bare(cache, DL_REPO)
    src = found['source_commit']
    comp.version = f'{info["version"]} ({found["variant"]})'
    comp.notes.append(f'binary matched docker-library/busybox dist-{ARCH[arch]} commit {found["dist_commit"]} '
                      f'({found["archive"]}); official-images commit {found["official_images_commit"]}; '
                      f'source commit {src}; variant {found["variant"]}')
    if not gitsrc.has_commit(bare, src):
        subprocess.run(['git', '-C', bare, 'fetch', '-q', '--depth', '1', 'origin', src], capture_output=True)
    builder = subprocess.run(['git', '-C', bare, 'show', f'{src}:{found["dir"]}/{found["variant"]}/Dockerfile.builder'],
                             capture_output=True, text=True).stdout
    if not builder:
        raise Unresolved(f'no Dockerfile.builder for {found["dir"]}/{found["variant"]} at {src}')
    env = dict(re.findall(r'^ENV\s+(\w+)[ =](\S+)', builder, re.M))
    if env.get('BUSYBOX_VERSION') != info['version']:
        raise VerificationError(f'Dockerfile.builder BUSYBOX_VERSION {env.get("BUSYBOX_VERSION")} != '
                                f'binary {info["version"]}')
    base = f'{rel_root}/busybox/{info["version"]}-{found["variant"]}-{src[:12]}'
    files = []
    tb = f'busybox-{info["version"]}.tar.bz2'
    p, url = cache.fetch([f'https://busybox.net/downloads/{tb}'], 'sha256', env['BUSYBOX_SHA256'])
    files.append((p, f'{base}/{tb}', url, f'sha256 = BUSYBOX_SHA256 in docker-library/busybox {src} Dockerfile.builder'))
    gp, desc = gitsrc.archive(cache, DL_REPO, src, workroot)
    files.append((gp, f'{base}/docker-library-busybox-{src[:12]}.tar.gz', f'{DL_REPO}@{src}',
                  desc + ' (build recipe, BusyBox .config generation and patches)'))
    if found['variant'] == 'uclibc':
        brv = env.get('BUILDROOT_VERSION')
        if not brv:
            raise Unresolved('uclibc variant without BUILDROOT_VERSION')
        tarball = f'buildroot-{brv}.tar.xz'
        sign = http_get(f'https://buildroot.org/downloads/{tarball}.sign').decode('utf-8', 'replace')
        want = _sign_sha256(sign, tarball)
        if not want:
            raise Unresolved(f'no SHA256 line for {tarball} in its .sign file')
        p, url = cache.fetch([f'https://buildroot.org/downloads/{tarball}'], 'sha256', want)
        files.append((p, f'{base}/{tarball}', url,
                      f'sha256 from the PGP clear-signed {tarball}.sign (signature itself not checked here)'))
        with lzma.open(p) as fh, tarfile.open(fileobj=fh, mode='r|') as tar:
            mk = hashfile = None
            for mem in tar:
                if mem.name.endswith('/package/uclibc/uclibc.mk'):
                    mk = tar.extractfile(mem).read().decode()
                elif mem.name.endswith('/package/uclibc/uclibc.hash'):
                    hashfile = tar.extractfile(mem).read().decode()
                if mk and hashfile:
                    break
        uv = re.search(r'^UCLIBC_VERSION\s*=\s*(\S+)', mk or '', re.M)
        if not uv:
            raise Unresolved(f'cannot read UCLIBC_VERSION from {tarball}')
        uname = f'uClibc-ng-{uv.group(1)}.tar.xz'
        uh = re.search(rf'^sha256\s+([0-9a-f]{{64}})\s+{re.escape(uname)}', hashfile or '', re.M)
        if not uh:
            raise Unresolved(f'no sha256 for {uname} in buildroot package/uclibc/uclibc.hash')
        p, url = cache.fetch([f'https://downloads.uclibc-ng.org/releases/{uv.group(1)}/{uname}'],
                             'sha256', uh.group(1))
        files.append((p, f'{base}/{uname}', url, f'sha256 from {tarball} package/uclibc/uclibc.hash'))
        comp.licence = 'GPL-2.0-only (BusyBox, Buildroot) AND LGPL-2.1-or-later (uClibc-ng, statically linked)'
        comp.families = ['GPL', 'LGPL']
        comp.notes.append('libgcc parts linked in are under the GCC Runtime Library Exception')
    elif found['variant'] == 'glibc':
        raise Unresolved('glibc variant: the Debian glibc build used by docker-library is not recorded; '
                         'add support before shipping such an image')
    else:
        comp.notes.append('musl variant: musl libc is MIT licensed; no further libc source required')
    return files


# ------------------------------------------------- Debian files in prometheus/busybox

def _deb_members(deb_bytes):
    """Yield (name, bytes) of the data archive members of a .deb."""
    if not deb_bytes.startswith(b'!<arch>\n'):
        raise VerificationError('not a .deb')
    pos = 8
    while pos < len(deb_bytes):
        hdr = deb_bytes[pos:pos + 60]
        name = hdr[:16].decode().strip().rstrip('/')
        size = int(hdr[48:58].decode().strip())
        body = deb_bytes[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
        if name.startswith('data.tar'):
            if name.endswith('.xz'):
                raw = lzma.decompress(body)
            elif name.endswith('.gz'):
                raw = gzip.decompress(body)
            elif name.endswith('.zst'):
                from compression import zstd
                raw = zstd.decompress(body)
            else:
                raw = body
            with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
                for mem in tar:
                    if mem.isfile():
                        yield mem.name.lstrip('./'), tar.extractfile(mem).read()


def _binary_versions(cache, pkg, created):
    data = cache.cached_json(f'{debian.SNAPSHOT}/mr/binary/{pkg}/', allow_404=True) or {}
    out = []
    for row in data.get('result', []):
        files = cache.cached_json(f'{debian.SNAPSHOT}/mr/binary/{pkg}/{debian.quote_url(row["binary_version"])}'
                                  f'/binfiles?fileinfo=1', allow_404=True) or {}
        for f in files.get('result', []):
            info = files['fileinfo'][f['hash']]
            first = min(i.get('first_seen', '') for i in info)
            if f.get('architecture') == 'all' and first[:8] <= created.replace('-', '')[:8]:
                out.append((first, row['binary_version'], row['source'], row['version'], f['hash']))
    return sorted(out, reverse=True)


def _pem_set(text):
    return {re.sub(r'\s+', '', b) for b in re.findall(
        r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', text, re.S)}


def debian_data_files(facts, image_ref, arch, cache, registry):
    """Identify the Debian versions of ca-certificates.crt and /etc/services by content."""
    if facts.get('dpkg_status') or facts.get('dpkg_status_d') or facts.get('apk_installed') \
            or facts.get('rpmdb_dir'):
        return 0
    loose = facts.get('loose_files') or {}
    created = (facts.get('created') or '')[:10]
    n = 0
    checks = []
    if 'etc/ssl/certs/ca-certificates.crt' in loose:
        want = _pem_set(loose['etc/ssl/certs/ca-certificates.crt']['text'])
        checks.append(('ca-certificates', 'etc/ssl/certs/ca-certificates.crt',
                       lambda files: _pem_set('\n'.join(
                           b.decode('ascii', 'replace') for n_, b in files
                           if n_.startswith('usr/share/ca-certificates/mozilla/'))) == want))
    if 'etc/services' in loose:
        want_s = loose['etc/services']['sha256']
        checks.append(('netbase', 'etc/services',
                       lambda files: any(n_ == 'etc/services' and hashlib.sha256(b).hexdigest() == want_s
                                         for n_, b in files)))
    for pkg, what, match in checks:
        hits = []
        for first, bver, src, sver, sha1 in _binary_versions(cache, pkg, created)[:40]:
            p, _u = cache.fetch([f'{debian.SNAPSHOT}/file/{sha1}'], 'sha1', sha1)
            if match(list(_deb_members(p.read_bytes()))):
                hits.append((src, sver, bver))
            elif hits:
                break  # versions are newest first; stop after the matching run
        if not hits:
            key = f'debian-file:{pkg}@unmatched'
            comp = registry.setdefault(key, Component(
                key=key, ecosystem='debian', name=pkg, version='(unmatched)', licence='GPL/MPL (Debian)',
                category='copyleft', families=['GPL', 'MPL']))
            comp.fetch = {'unmatched': f'/{what} matched no Debian {pkg} binary published before {created}'}
            comp.add_image(image_ref, arch, f'/{what}')
            continue
        for src, sver, bver in hits:
            key = f'debian:{src}@{sver}'
            if key not in registry:
                text = debian.copyright_from_source(cache, src, sver)
                cls = debian.classify_copyright(text or '')
                comp = Component(key=key, ecosystem='debian', name=src, version=sver,
                                 licence=cls.get('licence', ''), category=cls['category'], families=cls['families'])
                comp.notes.append('licence classified from debian/copyright in the verified source package')
                registry[key] = comp
            registry[key].add_image(image_ref, arch, f'/{what} identical to Debian {pkg} {bver} '
                                                      f'(no dpkg database; matched by content)')
            n += 1
    return n
