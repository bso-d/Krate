"""RPM packages (Red Hat UBI based images) -> source RPMs from Red Hat's public UBI
source repositories.

The rpm database is read without running the image's software: an SQLite rpmdb (RHEL 9)
is parsed here; a Berkeley DB rpmdb (RHEL 8) is queried with the image's own `rpm`
binary in a network-less throwaway container. Each SRPM is downloaded from
cdn-ubi.redhat.com and checked against the SHA-256 in that repository's repodata
(primary.xml), which repomd.xml references by checksum."""
from __future__ import annotations

import gzip
import re
import sqlite3
import struct
import subprocess
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from common import (Component, Unresolved, VerificationError, classify_expression, sha256_bytes,
                    sha256_file, slug)

UBI = 'https://cdn-ubi.redhat.com/content/public/ubi/dist'
TAGS = {1000: 'name', 1001: 'version', 1002: 'release', 1003: 'epoch', 1011: 'vendor',
        1014: 'license', 1022: 'arch', 1044: 'sourcerpm'}
QF = '%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{LICENSE}\\t%{SOURCERPM}\\t%{VENDOR}\\n'


def parse_header_blob(blob: bytes):
    il, dl = struct.unpack_from('>II', blob, 0)
    entries = blob[8:8 + 16 * il]
    store = blob[8 + 16 * il:8 + 16 * il + dl]
    out = {}
    for i in range(il):
        tag, typ, off, cnt = struct.unpack_from('>IIII', entries, i * 16)
        if tag not in TAGS:
            continue
        if typ in (6, 8, 9):
            end = store.index(b'\0', off)
            out[TAGS[tag]] = store[off:end].decode('utf-8', 'replace')
        elif typ == 4:
            out[TAGS[tag]] = str(struct.unpack_from('>I', store, off)[0])
    return out


def read_sqlite(dbdir: Path):
    # Work on a copy so a pending WAL is replayed without touching the extracted files.
    import shutil, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        for f in dbdir.iterdir():
            if f.name.startswith('rpmdb.sqlite'):
                shutil.copyfile(f, Path(tmp) / f.name)
        con = sqlite3.connect(str(Path(tmp) / 'rpmdb.sqlite'))
        try:
            rows = [parse_header_blob(bytes(b)) for (b,) in con.execute('SELECT blob FROM Packages')]
        finally:
            con.close()
    return [r for r in rows if r.get('name') and r.get('name') != 'gpg-pubkey']


def read_with_image_rpm(image_ref, arch):
    name = f'krate-collect-sources-rpmq-{uuid.uuid4().hex[:10]}'
    proc = subprocess.run(['docker', 'run', '--rm', '--name', name, '--network', 'none',
                           '--platform', f'linux/{arch}', '--entrypoint', 'rpm', image_ref,
                           '-qa', '--qf', QF], capture_output=True, text=True, timeout=300)
    if proc.returncode:
        raise Unresolved(f'rpm -qa in {image_ref} failed: {proc.stderr[-300:]}')
    rows = []
    for line in proc.stdout.splitlines():
        p = line.split('\t')
        if len(p) == 8 and p[0] != 'gpg-pubkey':
            rows.append(dict(zip(('name', 'epoch', 'version', 'release', 'arch', 'license',
                                  'sourcerpm', 'vendor'), p)))
    return rows


def installed(facts):
    d = facts.get('rpmdb_dir')
    if not d:
        return []
    d = Path(d)
    if (d / 'rpmdb.sqlite').exists():
        return read_sqlite(d)
    return read_with_image_rpm(facts['resolved_ref'], facts['arch'])


def _image_epoch(facts):
    import datetime as _dt
    c = (facts.get('created') or '')[:19]
    try:
        return int(_dt.datetime.strptime(c, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=_dt.timezone.utc).timestamp())
    except ValueError:
        return None


def rhel_major(facts):
    for text in (facts.get('os_release') or {}).values():
        m = re.search(r'^VERSION_ID="?(\d+)', text, re.M)
        if m:
            return m.group(1)
    return None


def is_red_hat(row):
    return 'red hat' in (row.get('vendor') or '').lower()


def components(facts, image_ref, arch, cache, registry):
    rows = installed(facts)
    if not rows:
        return 0
    major = rhel_major(facts)
    facts['_rpm_rows'] = rows
    groups = {}
    for r in rows:
        if 'azul' in (r.get('vendor') or '').lower():
            continue  # JDK handler
        groups.setdefault(r.get('sourcerpm') or f'{r["name"]}-{r["version"]}-{r["release"]}.nosrc', []).append(r)
    for srpm, pkgs in sorted(groups.items()):
        key = f'rpm:{srpm}'
        comp = registry.get(key)
        m = re.match(r'^(.+)-([^-]+)-([^-]+)\.(no)?src\.rpm$', srpm)
        if comp is None:
            licences = sorted({p.get('license') or '' for p in pkgs})
            results = [classify_expression(l) for l in licences]
            cat = ('copyleft' if any(r['category'] == 'copyleft' for r in results) else
                   'unknown' if any(r['category'] == 'unknown' for r in results) else
                   'elected-permissive' if any(r['category'] == 'elected-permissive' for r in results)
                   else 'permissive')
            comp = Component(key=key, ecosystem='rpm', name=m.group(1) if m else srpm,
                             version=f'{m.group(2)}-{m.group(3)}' if m else '', licence=' AND '.join(licences),
                             category=cat, families=sorted({f for r in results for f in r['families']}))
            comp.fetch = {'srpm': srpm, 'majors': set(), 'basearch': set(),
                          'vendors': sorted({p.get('vendor') or '' for p in pkgs})}
            registry[key] = comp
        comp.fetch['majors'].add(major)
        m_base = re.search(r'/(ubi\d+)-?(micro|minimal|init)?/images/([\d.]+-[\d.]+)', (facts.get('labels') or {}).get('url', ''))
        if m_base:  # the exact UBI base image (e.g. ubi8-minimal 8.9-1161) is searched first
            base_repo = f'{m_base.group(1)}/ubi' + (f'-{m_base.group(2)}' if m_base.group(2) else '')
            comp.fetch.setdefault('preferred', set()).add((base_repo, f'{m_base.group(3)}-source'))
        built = _image_epoch(facts)
        if built and (comp.fetch.get('built_before') or 0) < built:
            comp.fetch['built_before'] = built
        comp.fetch['basearch'].add('aarch64' if arch == 'arm64' else 'x86_64')
        for p in pkgs:
            comp.add_image(image_ref, arch, f'{p["name"]}-{p["version"]}-{p["release"]}.{p["arch"]} '
                                            f'[{p.get("vendor")}] License: {p.get("license")}')
    return len(groups)


def repo_index(cache, major, basearch, repo):
    """Map SRPM file name -> (sha256, size, url) for one UBI source repository."""
    base = f'{UBI}/ubi{major}/{major}/{basearch}/{repo}/source/SRPMS'
    repomd = cache.cached_get(f'{base}/repodata/repomd.xml', max_age=6 * 3600, allow_404=True)
    if not repomd:
        return {}
    ns = {'r': 'http://linux.duke.edu/metadata/repo', 'c': 'http://linux.duke.edu/metadata/common'}
    root = ET.fromstring(repomd)
    data = root.find("r:data[@type='primary']", ns)
    href = data.find('r:location', ns).get('href')
    want = data.find('r:checksum', ns).text
    algo = data.find('r:checksum', ns).get('type')
    raw = cache.cached_get(f'{base}/{href}')
    if sha256_bytes(raw, algo) != want:
        raise VerificationError(f'{base}/{href}: repodata checksum mismatch')
    xml = gzip.decompress(raw) if href.endswith('.gz') else raw
    out = {}
    for _ev, el in ET.iterparse(__import__('io').BytesIO(xml)):
        if el.tag.endswith('}package'):
            loc = el.find('c:location', ns).get('href')
            ck = el.find('c:checksum', ns)
            size = el.find('c:size', ns).get('package')
            out[loc.rsplit('/', 1)[-1]] = (ck.get('type'), ck.text, int(size), f'{base}/{loc}')
            el.clear()
    return out


_INDEX = {}


def find_srpm(cache, srpm, majors, basearches):
    for major in sorted(m for m in majors if m):
        for basearch in sorted(basearches):
            for repo in ('baseos', 'appstream', 'codeready-builder'):
                k = (major, basearch, repo)
                if k not in _INDEX:
                    _INDEX[k] = repo_index(cache, major, basearch, repo)
                if srpm in _INDEX[k]:
                    return _INDEX[k][srpm], k
    return None, None


def fetch(comp, cache, out_dir, rel_root):
    srpm = comp.fetch['srpm']
    if srpm.endswith('.nosrc.rpm') or not srpm.endswith('.src.rpm'):
        raise Unresolved(f'package records no source RPM ({srpm}); vendor {comp.fetch["vendors"]}')
    hit, where = find_srpm(cache, srpm, comp.fetch['majors'], comp.fetch['basearch'])
    if not hit:
        got = srpm_from_source_container(cache, srpm, comp.fetch['majors'], comp.fetch.get('built_before'),
                                         comp.fetch.get('preferred') or ())
        if got:
            path, url, how = got
            return [(path, f'{rel_root}/rpm/{slug(comp.name)}/{srpm}', url, how)]
        vend = ', '.join(comp.fetch['vendors'])
        raise Unresolved(f'{srpm} is not in the public UBI {"/".join(sorted(m for m in comp.fetch["majors"] if m))} '
                         f'source repositories (baseos/appstream/codeready-builder, newest builds only) nor in the '
                         f'Red Hat UBI source container images searched (ubi-micro/ubi-minimal/ubi built before the '
                         f'image); vendor: {vend}')
    algo, digest, size, url = hit
    path, url = cache.fetch([url], algo, digest, size=size)
    return [(path, f'{rel_root}/rpm/{slug(comp.name)}/{srpm}', url,
             f'{algo} from UBI {where[0]} {where[2]} source repodata (primary.xml, checksum-pinned by repomd.xml)')]


# ---------------------------------------------------------------- source containers
# UBI source repositories only keep the newest build of each package. Older SRPMs are
# still published inside Red Hat's source container images (<repo>:<tag>-source), one
# SRPM per layer, addressed by the layer digest listed in the registry manifest.

REGISTRY = 'https://registry.access.redhat.com'
SOURCE_REPOS = ('ubi{m}/ubi-micro', 'ubi{m}/ubi-minimal', 'ubi{m}/ubi')
ACCEPT = 'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'


def _tags(cache, repo):
    import json as _json
    key = cache.meta_path(f'rh-tags:{repo}')
    if key.exists() and __import__('time').time() - key.stat().st_mtime < 6 * 3600:
        return _json.loads(key.read_text())
    import urllib.request
    url, tags = f'{REGISTRY}/v2/{repo}/tags/list?n=100', []
    while url:
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'krate-collect-sources'}),
                                    timeout=60) as r:
            tags += _json.loads(r.read()).get('tags') or []
            m = re.search(r'<([^>]+)>', r.headers.get('Link') or '')
        url = REGISTRY + m.group(1) if m else None
    key.write_text(_json.dumps(tags))
    return tags


def _layer_names(cache, repo, digest):
    """File names inside a source-container layer, read from the start of the stream."""
    import json as _json
    import tarfile as _tar
    import urllib.request
    key = cache.meta_path(f'rh-layer-names:{digest}')
    if key.exists():
        return _json.loads(key.read_text())
    req = urllib.request.Request(f'{REGISTRY}/v2/{repo}/blobs/{digest}', headers={'User-Agent': 'krate-collect-sources'})
    names = []
    with urllib.request.urlopen(req, timeout=120) as r, _tar.open(fileobj=r, mode='r|gz') as tar:
        for mem in tar:
            names.append(mem.name)
            if mem.name.endswith('.src.rpm'):
                break
    key.write_text(_json.dumps(names))
    return names


def _search_tag(cache, repo, tag, srpm):
    man = _manifest(cache, repo, tag)
    for layer in (man or {}).get('layers', []):
        try:
            names = _layer_names(cache, repo, layer['digest'])
        except Exception:
            continue
        if any(n.rsplit('/', 1)[-1] == srpm for n in names):
            return f'{REGISTRY}/v2/{repo}/blobs/{layer["digest"]}', layer['digest'], f'{repo}:{tag}', layer['size']
    return None


def find_in_source_containers(cache, srpm, major, built_before, preferred=()):
    """Return (layer url, layer digest, repo:tag, size) of a source-container layer holding srpm."""
    for repo, tag in sorted(preferred):
        if repo.startswith(f'ubi{major}/'):
            hit = _search_tag(cache, repo, tag, srpm)
            if hit:
                return hit
    for tmpl in SOURCE_REPOS:
        repo = tmpl.format(m=major)
        try:
            tags = _tags(cache, repo)
        except Exception:
            continue
        cands = []
        for t in tags:
            m = re.match(rf'^{major}\.\d+-(\d+)-source$', t)
            if m and (built_before is None or int(m.group(1)) <= built_before):
                cands.append((int(m.group(1)), t))
        for _ts, tag in sorted(cands, reverse=True)[:15]:
            hit = _search_tag(cache, repo, tag, srpm)
            if hit:
                return hit
    return None


def _manifest(cache, repo, tag):
    import json as _json
    import urllib.request
    key = cache.meta_path(f'rh-manifest:{repo}:{tag}')
    if key.exists():
        return _json.loads(key.read_text())
    req = urllib.request.Request(f'{REGISTRY}/v2/{repo}/manifests/{tag}',
                                 headers={'User-Agent': 'krate-collect-sources', 'Accept': ACCEPT})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
    except Exception:
        return None
    key.write_text(data.decode())
    return _json.loads(data)


def srpm_from_source_container(cache, srpm, majors, built_before, preferred=()):
    import tarfile as _tar
    import uuid as _uuid
    for major in sorted(m for m in majors if m):
        hit = find_in_source_containers(cache, srpm, major, built_before, preferred)
        if not hit:
            continue
        url, digest, where, size = hit
        layer, _u = cache.fetch([url], 'sha256', digest.split(':', 1)[1], size=size)
        tmp = Path(cache.root) / 'tmp' / f'{_uuid.uuid4().hex}-{srpm}'
        with _tar.open(layer, 'r:gz') as tar:
            members = {m.name: m for m in tar.getmembers()}
            link = next((m for m in members.values() if m.name.rsplit('/', 1)[-1] == srpm), None)
            target = link
            if link is not None and link.issym():
                # rpm_dir/<srpm> -> ../blobs/sha256/<sha256 of the SRPM>
                target = members.get('./' + link.linkname.replace('../', '')) or \
                    members.get(link.linkname.replace('../', ''))
            if target is not None and target.isfile():
                with tar.extractfile(target) as src, open(tmp, 'wb') as out:
                    out.write(src.read())
                want = target.name.rsplit('/', 1)[-1]
                if re.fullmatch(r'[0-9a-f]{64}', want) and sha256_file(tmp) != want:
                    tmp.unlink()
                    raise VerificationError(f'{srpm} in {where}: content does not match its blob name {want}')
        if not tmp.exists():
            continue
        path, _d = cache.adopt(tmp)
        return path, url, (f'extracted from layer {digest} of Red Hat source container {where}: layer '
                           'sha256 = registry manifest digest, SRPM sha256 = its content-addressed blob name')
    return None
