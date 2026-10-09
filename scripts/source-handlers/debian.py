"""Debian packages: dpkg status (or distroless status.d) -> source packages.

Source files come from the Debian archive (deb.debian.org / security mirror) or
snapshot.debian.org. Every file is checked twice: against the SHA-1 snapshot.debian.org
publishes for that exact source version (the snapshot file id), and against the SHA-256
recorded in the version's signed .dsc (Checksums-Sha256)."""
from __future__ import annotations

import lzma
import re
import tarfile
import gzip
import bz2

from common import (Component, Unresolved, VerificationError, classify_expression,
                    classify_texts, quote_url, sha256_file, slug)

SNAPSHOT = 'https://snapshot.debian.org'


def parse_control(text):
    """Parse RFC822-style dpkg stanzas into a list of dicts."""
    out = []
    for block in re.split(r'\n\s*\n', text.strip()):
        fields, key = {}, None
        for line in block.splitlines():
            if line.startswith((' ', '\t')) and key:
                fields[key] += '\n' + line.strip()
            elif ':' in line:
                key, v = line.split(':', 1)
                fields[key] = v.strip()
        if fields:
            out.append(fields)
    return out


def installed_packages(facts):
    """Installed binary packages with their source package and source version."""
    stanzas = []
    if facts.get('dpkg_status'):
        stanzas += parse_control(facts['dpkg_status'])
    for text in (facts.get('dpkg_status_d') or {}).values():
        stanzas += parse_control(text)
    pkgs = []
    for f in stanzas:
        status = f.get('Status', 'install ok installed')
        if 'Package' not in f or not status.endswith(' installed'):
            continue
        src, sver = f['Package'], f['Version']
        if f.get('Source'):
            m = re.match(r'^(\S+)(?:\s+\(([^)]+)\))?', f['Source'])
            src = m.group(1)
            sver = m.group(2) or f['Version']
        built_using = []
        for field in ('Built-Using', 'Static-Built-Using'):
            for item in (f.get(field) or '').split(','):
                m = re.match(r'^\s*(\S+)\s+\(=\s*([^)]+)\)', item)
                if m:
                    built_using.append((m.group(1), m.group(2).strip(), field))
        pkgs.append({'package': f['Package'], 'version': f['Version'], 'arch': f.get('Architecture'),
                     'source': src, 'source_version': sver, 'built_using': built_using})
    return pkgs


def dep5_licences(text):
    """License short names of a machine-readable debian/copyright, else None."""
    if not re.search(r'^Format:\s*\S*(copyright-format|dep5|DEP-5)', text, re.M | re.I):
        return None
    names = []
    for stanza in parse_control(text):
        lic = stanza.get('License')
        if lic:
            names.append(lic.split('\n', 1)[0].strip())
    return names


def classify_copyright(text):
    names = dep5_licences(text)
    if names:
        results = [classify_expression(n.replace(',', ' and ')) for n in names]
        fams = sorted({f for r in results for f in r['families']})
        if any(r['category'] == 'copyleft' for r in results):
            return {'category': 'copyleft', 'families': fams, 'elected': None,
                    'licence': ' AND '.join(sorted(set(names)))[:400]}
        return {'category': 'permissive', 'families': fams, 'elected': None,
                'licence': ' AND '.join(sorted(set(names)))[:400]}
    r = classify_texts([text])
    r['licence'] = 'see debian/copyright (free-form)'
    return r


def _pool_prefix(src):
    return src[:4] if src.startswith('lib') and len(src) > 3 else src[0]


def srcfiles(cache, src, ver):
    """snapshot.debian.org: the files of one source version with their SHA-1 ids."""
    url = f'{SNAPSHOT}/mr/package/{quote_url(src)}/{quote_url(ver)}/srcfiles?fileinfo=1'
    data = cache.cached_json(url, allow_404=True)
    if not data or not data.get('result'):
        raise Unresolved(f'snapshot.debian.org has no source {src} {ver}')
    files = []
    for row in data['result']:
        info = data['fileinfo'][row['hash']]
        # The same bytes can be known under several names (e.g. a shared orig tarball);
        # list the file under every name so the .dsc entry can be matched.
        for name in sorted({i['name'] for i in info}):
            rows = [i for i in info if i['name'] == name]
            files.append({'sha1': row['hash'], 'name': name, 'size': rows[0].get('size'),
                          'first_seen': min(i.get('first_seen', '') for i in rows),
                          'archives': sorted({i['archive_name'] for i in info}),
                          'path': rows[0].get('path')})
    return files


def parse_dsc(text):
    """Checksums-Sha256 of a .dsc (clear-signed or not)."""
    body = text
    m = re.search(r'-----BEGIN PGP SIGNED MESSAGE-----.*?\n\n(.*?)-----BEGIN PGP SIGNATURE-----', text, re.S)
    if m:
        body = m.group(1)
    fields = parse_control(body)[0]
    sums = {}
    for line in fields.get('Checksums-Sha256', '').splitlines():
        parts = line.split()
        if len(parts) == 3:
            sums[parts[2]] = (parts[0], int(parts[1]))
    return fields, sums, bool(m)


def _candidates(src, name, sha1, archives):
    pre = _pool_prefix(src)
    urls = []
    if any('security' in a for a in archives):
        urls.append(f'https://deb.debian.org/debian-security/pool/updates/main/{pre}/{src}/{name}')
    urls.append(f'https://deb.debian.org/debian/pool/main/{pre}/{src}/{name}')
    urls.append(f'{SNAPSHOT}/file/{sha1}')
    return urls


def fetch_source(cache, src, ver):
    """Download and verify every file of a Debian source version.

    Returns a list of (cached_path, name, origin_url, verification)."""
    files = srcfiles(cache, src, ver)
    dscs = [f for f in files if f['name'].endswith('.dsc')]
    if len(dscs) != 1:
        raise Unresolved(f'{src} {ver}: expected one .dsc on snapshot.debian.org, found {len(dscs)}')
    dsc = dscs[0]
    dsc_path, dsc_url = cache.fetch(_candidates(src, dsc['name'], dsc['sha1'], dsc['archives'])[-1:],
                                    'sha1', dsc['sha1'])
    fields, sums, signed = parse_dsc(dsc_path.read_text(errors='replace'))
    if fields.get('Source') != src or fields.get('Version') != ver:
        raise VerificationError(f'{dsc["name"]}: Source/Version {fields.get("Source")} '
                                f'{fields.get("Version")} != {src} {ver}')
    out = [(dsc_path, dsc['name'], dsc_url,
            f'sha1 {dsc["sha1"]} = snapshot.debian.org file id for {src} {ver}'
            + ('; clear-signed .dsc (signature not checked here)' if signed else ''))]
    listed = {f['name']: f for f in files}
    for name, (sha256, size) in sorted(sums.items()):
        meta = listed.get(name)
        if not meta:
            raise Unresolved(f'{src} {ver}: {name} is in the .dsc but not on snapshot.debian.org')
        path, url = cache.fetch(_candidates(src, name, meta['sha1'], meta['archives']), 'sha256', sha256,
                                size=size)
        got_sha1 = sha256_file(path, 'sha1')
        if got_sha1 != meta['sha1']:
            raise VerificationError(f'{name}: sha1 {got_sha1} != snapshot {meta["sha1"]}')
        out.append((path, name, url, 'sha256 from .dsc Checksums-Sha256 and sha1 = snapshot.debian.org id'))
    return out


def copyright_from_source(cache, src, ver):
    """Read debian/copyright from the verified Debian packaging tarball."""
    for path, name, _url, _v in fetch_source(cache, src, ver):
        if re.search(r'\.(debian|diff)\.', name) or (re.search(r'\.tar\.', name) and '.orig' not in name):
            if name.endswith('.diff.gz'):
                text = gzip.decompress(path.read_bytes()).decode('utf-8', 'replace')
                m = re.search(r'\+\+\+ [^\n]*/debian/copyright\n@@[^\n]*\n((?:\+[^\n]*\n)+)', text)
                if m:
                    return '\n'.join(l[1:] for l in m.group(1).splitlines())
                continue
            opener = {'.xz': lzma.open, '.gz': gzip.open, '.bz2': bz2.open}
            ext = '.' + name.rsplit('.', 1)[-1]
            try:
                with opener.get(ext, open)(path, 'rb') as fh, tarfile.open(fileobj=fh, mode='r|') as tar:
                    for m in tar:
                        if re.fullmatch(r'(\./)?([^/]+/)?debian/copyright', m.name) and m.isfile():
                            return tar.extractfile(m).read().decode('utf-8', 'replace')
            except (tarfile.TarError, OSError, lzma.LZMAError, EOFError):
                continue
    return None


def components(facts, image_ref, arch, cache, registry):
    """Register Debian source packages for one image platform."""
    pkgs = installed_packages(facts)
    if not pkgs:
        return 0
    copyrights = facts.get('copyright') or {}
    by_source = {}
    for p in pkgs:
        by_source.setdefault((p['source'], p['source_version']), []).append(p)
        for (bsrc, bver, field) in p['built_using']:
            by_source.setdefault((bsrc, bver), []).append(
                {'package': f'{p["package"]} ({field})', 'version': p['version'], 'arch': p['arch'],
                 'source': bsrc, 'source_version': bver, 'built_using': []})
    for (src, ver), binaries in sorted(by_source.items()):
        key = f'debian:{src}@{ver}'
        comp = registry.get(key)
        if comp is None:
            text = next((copyrights[b['package']] for b in binaries if b['package'] in copyrights), None)
            origin = 'image /usr/share/doc/<package>/copyright'
            if text is None:
                try:
                    text = copyright_from_source(cache, src, ver)
                    origin = 'debian/copyright in the verified source package'
                except Unresolved:
                    text = None
            if text is None:
                cls = {'category': 'unknown', 'families': [], 'licence': 'copyright file unavailable'}
            else:
                cls = classify_copyright(text)
            comp = Component(key=key, ecosystem='debian', name=src, version=ver,
                             licence=cls.get('licence', ''), category=cls['category'],
                             families=cls['families'])
            comp.notes.append(f'licence classified from {origin}')
            registry[key] = comp
        for b in binaries:
            comp.add_image(image_ref, arch, f'{b["package"]} {b["version"]} ({b["arch"]})')
    return len(by_source)


def fetch(comp, cache, out_dir, rel_root):
    files = []
    for path, name, url, how in fetch_source(cache, comp.name, comp.version):
        rel = f'{rel_root}/debian/{slug(comp.name)}/{slug(comp.version)}/{name}'
        files.append((path, rel, url, how))
    return files
