"""Offline inventory of one container image platform.

The image is never run: `docker create` + `docker export` streams the filesystem into
this reader, which keeps only package databases, licence evidence, JDK release files,
JAR metadata, Go build information and BusyBox identification. The container is
removed by its exact name afterwards."""
from __future__ import annotations

import io
import json
import re
import struct
import subprocess
import tarfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from common import log, run, sha256_bytes

FACTS_VERSION = 5
MAX_MEMBER = 600 << 20
GO_MAGIC = b'\xff Go buildinf:'
JAR_SUFFIXES = ('.jar', '.war', '.ear')


# ---------------------------------------------------------------- docker

def _inspect(ref, arch):
    proc = subprocess.run(['docker', 'image', 'inspect', '--platform', f'linux/{arch}', ref,
                           '--format', '{{json .}}'], capture_output=True, text=True)
    if proc.returncode:  # Docker 28.0 and older have no --platform on image inspect
        proc = subprocess.run(['docker', 'image', 'inspect', ref, '--format', '{{json .}}'],
                              capture_output=True, text=True)
    if proc.returncode:
        return None
    data = json.loads(proc.stdout)
    if data.get('Architecture') != arch:
        return None
    return data


def resolve_image(candidates, arch, *, pull=True, expected_id=None):
    """Return (ref, inspect) for the first candidate present locally for arch, pulling
    registry references by digest when allowed."""
    for ref in candidates:
        data = _inspect(ref, arch)
        if data:
            return ref, data
    if pull:
        for ref in candidates:
            if '@sha256:' not in ref or ref.startswith('sha256:') or ref.startswith('krate/'):
                continue
            log(f'pulling {ref} for linux/{arch}')
            proc = subprocess.run(['docker', 'pull', '-q', '--platform', f'linux/{arch}', ref],
                                  capture_output=True, text=True)
            if proc.returncode == 0:
                data = _inspect(ref, arch)
                if data:
                    return ref, data
            else:
                log(f'pull failed: {proc.stderr.strip()[-300:]}')
    return None, None


# ---------------------------------------------------------------- ELF

def elf_info(data: bytes):
    """Minimal ELF reader: static/dynamic, interpreter, .comment strings."""
    info = {'static': None, 'interp': None, 'comment': [], 'machine': None}
    if data[:4] != b'\x7fELF' or data[4] != 2:   # 64-bit only (all target images are)
        return info
    endian = '<' if data[5] == 1 else '>'
    try:
        (e_type, e_machine, _v, _entry, e_phoff, e_shoff, _flags, _ehsize, e_phentsize,
         e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            endian + 'HHIQQQIHHHHHH', data, 16)
        info['machine'] = e_machine
        has_dynamic = False
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, _pf, p_offset, _va, _pa, p_filesz = struct.unpack_from(endian + 'IIQQQQ', data, off)
            if p_type == 3:
                info['interp'] = data[p_offset:p_offset + p_filesz].rstrip(b'\0').decode(errors='replace')
            if p_type == 2:
                has_dynamic = True
        info['static'] = info['interp'] is None and not has_dynamic
        if e_shoff and e_shnum and e_shstrndx < e_shnum:
            sections = []
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                sh_name, _t, _f, _a, sh_offset, sh_size = struct.unpack_from(endian + 'IIQQQQ', data, off)
                sections.append((sh_name, sh_offset, sh_size))
            _n, str_off, str_size = sections[e_shstrndx]
            names = data[str_off:str_off + str_size]
            for sh_name, sh_offset, sh_size in sections:
                name = names[sh_name:names.index(b'\0', sh_name)]
                if name == b'.comment':
                    raw = data[sh_offset:sh_offset + sh_size]
                    info['comment'] = sorted({c.decode(errors='replace') for c in raw.split(b'\0') if c})
    except (struct.error, ValueError, IndexError):
        pass
    return info


def parse_go_version_m(text):
    """Parse `go version -m` output into a dict."""
    out = {'go': None, 'path': None, 'main': None, 'deps': [], 'build': {}}
    lines = text.splitlines()
    if lines:
        m = re.match(r'^.*?: (go\S+)', lines[0])
        out['go'] = m.group(1) if m else None
    last = None
    for line in lines[1:]:
        parts = line.strip('\t').split('\t')
        kind = parts[0]
        if kind == 'path':
            out['path'] = parts[1]
        elif kind == 'mod':
            out['main'] = {'path': parts[1], 'version': parts[2] if len(parts) > 2 else '',
                           'sum': parts[3] if len(parts) > 3 else ''}
        elif kind == 'dep':
            last = {'path': parts[1], 'version': parts[2] if len(parts) > 2 else '',
                    'sum': parts[3] if len(parts) > 3 else '', 'replace': None}
            out['deps'].append(last)
        elif kind == '=>' and last is not None:
            last['replace'] = {'path': parts[1], 'version': parts[2] if len(parts) > 2 else '',
                               'sum': parts[3] if len(parts) > 3 else ''}
        elif kind == 'build':
            k, _, v = parts[1].partition('=')
            out['build'][k] = v
    return out


# ---------------------------------------------------------------- JAR

def _props(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def _manifest(text):
    out, key = {}, None
    for line in text.splitlines():
        if line.startswith(' ') and key:
            out[key] += line[1:]
        elif ':' in line:
            key, v = line.split(':', 1)
            out[key] = v.strip()
    return {k: v for k, v in out.items() if k in (
        'Implementation-Title', 'Implementation-Version', 'Implementation-Vendor',
        'Bundle-SymbolicName', 'Bundle-Version', 'Bundle-License', 'Automatic-Module-Name',
        'Implementation-Vendor-Id', 'Specification-Title')}


def scan_jar(data: bytes, path: str, depth=0):
    rec = {'path': path, 'sha1': sha256_bytes(data, 'sha1'), 'sha256': sha256_bytes(data),
           'size': len(data), 'maven': [], 'manifest': {}, 'licence_files': {}, 'nested': []}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        rec['error'] = 'not a zip'
        return rec
    names = z.namelist()
    for name in names:
        m = re.fullmatch(r'META-INF/maven/([^/]+)/([^/]+)/pom\.properties', name)
        if m:
            props = _props(z.read(name).decode('utf-8', 'replace'))
            pom_name = name[:-len('pom.properties')] + 'pom.xml'
            pom = z.read(pom_name)[:400_000].decode('utf-8', 'replace') if pom_name in names else ''
            rec['maven'].append({'groupId': props.get('groupId', m.group(1)),
                                 'artifactId': props.get('artifactId', m.group(2)),
                                 'version': props.get('version', ''), 'pom': pom})
        elif name == 'META-INF/MANIFEST.MF':
            rec['manifest'] = _manifest(z.read(name).decode('utf-8', 'replace'))
        elif re.fullmatch(r'(META-INF/)?(LICEN[SC]E|COPYING|NOTICE)[^/]*', name, re.I) \
                and not name.endswith('/'):
            rec['licence_files'][name] = z.read(name)[:12000].decode('utf-8', 'replace')
        elif name.endswith(JAR_SUFFIXES) and depth < 2 and not name.endswith('/'):
            rec['nested'].append(scan_jar(z.read(name), f'{path}!/{name}', depth + 1))
    return rec


# ---------------------------------------------------------------- export scan

def _text(f, limit=4 << 20):
    return f.read(limit).decode('utf-8', 'replace')


def scan_container(cid, workdir: Path, go_bin='go'):
    facts = {'os_release': {}, 'dpkg_status': None, 'dpkg_status_d': {}, 'copyright': {},
             'apk_installed': None, 'rpmdb_dir': None, 'jdk_release': {}, 'jars': [],
             'go_binaries': {}, 'busybox': {}, 'elf_static_glibc': {}, 'python': {},
             'pip_vendor': {}, 'npm': {}, 'symlinks': {}, 'files': 0, 'bytes': 0,
             'loose_files': {}, 'python_installer': {}}
    rpm_dir = workdir / 'rpmdb'
    proc = subprocess.Popen(['docker', 'export', cid], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout, mode='r|') as tar:
            for m in tar:
                name = m.name.lstrip('./')
                if m.issym() or m.islnk():
                    if name in ('etc/os-release', 'bin/sh', 'bin/busybox') or name.startswith('usr/share/doc/'):
                        facts['symlinks'][name] = m.linkname
                    continue
                if not m.isfile():
                    continue
                facts['files'] += 1
                facts['bytes'] += m.size
                p = PurePosixPath(name)
                base = p.name
                if name in ('etc/os-release', 'usr/lib/os-release'):
                    facts['os_release'][name] = _text(tar.extractfile(m))
                elif name == 'var/lib/dpkg/status':
                    facts['dpkg_status'] = _text(tar.extractfile(m), 64 << 20)
                elif name.startswith('var/lib/dpkg/status.d/') and not base.endswith('.md5sums'):
                    facts['dpkg_status_d'][base] = _text(tar.extractfile(m))
                elif re.fullmatch(r'usr/share/doc/[^/]+/copyright', name):
                    facts['copyright'][p.parent.name] = _text(tar.extractfile(m), 2 << 20)
                elif name == 'lib/apk/db/installed':
                    facts['apk_installed'] = _text(tar.extractfile(m), 64 << 20)
                elif name.startswith(('var/lib/rpm/', 'usr/lib/sysimage/rpm/')) and m.size < 512 << 20:
                    rpm_dir.mkdir(parents=True, exist_ok=True)
                    (rpm_dir / base).write_bytes(tar.extractfile(m).read())
                    facts['rpmdb_dir'] = str(rpm_dir)
                elif base == 'release' and m.size < 65536:
                    data = tar.extractfile(m).read()
                    if b'JAVA_VERSION=' in data:
                        facts['jdk_release'][name] = data.decode('utf-8', 'replace')
                elif base.endswith(JAR_SUFFIXES) and m.size < MAX_MEMBER:
                    facts['jars'].append(scan_jar(tar.extractfile(m).read(), name))
                elif re.search(r'/(site|dist)-packages/[^/]+\.dist-info/METADATA$', name) or \
                        re.search(r'/(site|dist)-packages/[^/]+\.egg-info/PKG-INFO$', name):
                    facts['python'][name] = _text(tar.extractfile(m), 1 << 20)
                elif re.search(r'/(site|dist)-packages/[^/]+\.dist-info/INSTALLER$', name):
                    facts['python_installer'][name] = _text(tar.extractfile(m), 200).strip()
                elif name in ('etc/services', 'etc/ssl/certs/ca-certificates.crt', 'etc/nsswitch.conf'):
                    data = tar.extractfile(m).read()
                    facts['loose_files'][name] = {'sha256': sha256_bytes(data),
                                                  'text': data.decode('utf-8', 'replace')}
                elif name.endswith('/_vendor/vendor.txt'):
                    facts['pip_vendor'][name] = _text(tar.extractfile(m))
                elif re.search(r'(^|/)node_modules/(@[^/]+/)?[^/]+/package\.json$', name) and m.size < 1 << 20:
                    try:
                        pj = json.loads(tar.extractfile(m).read())
                        facts['npm'][name] = {'name': pj.get('name'), 'version': pj.get('version'),
                                              'license': pj.get('license') if isinstance(pj.get('license'), str)
                                              else json.dumps(pj.get('license') or pj.get('licenses'))}
                    except (ValueError, AttributeError):
                        pass
                elif m.size > 4096 and m.size < MAX_MEMBER and (m.mode & 0o111 or '.so' in base):
                    f = tar.extractfile(m)
                    head = f.read(4)
                    if head != b'\x7fELF':
                        continue
                    data = head + f.read()
                    if base == 'busybox' or (b'Usage: busybox' in data and b'BusyBox v1.' in data):
                        mv = re.search(rb'BusyBox v(1\.\d+\.\d+) \(([0-9-]+ [0-9:]+) UTC\)', data) or \
                            re.search(rb'BusyBox v(1\.\d+\.\d+)()', data)
                        libc = ('glibc' if b'GLIBC_' in data or b'GNU C Library' in data else
                                'musl' if b'No error information' in data else
                                'uclibc' if elf_info(data)['static'] else 'unknown')
                        facts['busybox'][name] = {'version': mv.group(1).decode() if mv else None,
                                                  'built': mv.group(2).decode() if mv and mv.group(2) else None,
                                                  'libc': libc, 'elf': elf_info(data),
                                                  'sha256': sha256_bytes(data)}
                    mg = re.search(rb'GNU C Library \(([^)]*)\) (?:stable|development) release version ([0-9.]+)', data)
                    if mg:
                        facts.setdefault('glibc_banner', {})[name] = [mg.group(1).decode(), mg.group(2).decode()]
                    if GO_MAGIC in data:
                        tmp = workdir / ('gobin-' + uuid.uuid4().hex)
                        tmp.write_bytes(data)
                        try:
                            text = subprocess.run([go_bin, 'version', '-m', str(tmp)], capture_output=True,
                                                  text=True).stdout
                        finally:
                            tmp.unlink()
                        info = parse_go_version_m(text)
                        ei = elf_info(data)
                        info['elf'] = ei
                        info['sha256'] = sha256_bytes(data)
                        cgo = info['build'].get('CGO_ENABLED') == '1'
                        glibc_markers = [s.decode() for s in (b'GLIBC_TUNABLES', b'glibc.rtld.', b'glibc.malloc.',
                                                               b'GNU C Library') if s in data]
                        mvers = sorted({v.decode() for v in re.findall(rb'GLIBC_2\.\d+(?:\.\d+)?', data)})
                        info['cgo'] = cgo
                        info['static_glibc'] = bool(cgo and ei['static'] and glibc_markers and
                                                    'musl' not in ' '.join(ei['comment']).lower())
                        info['glibc_markers'] = glibc_markers
                        info['glibc_symbol_versions'] = mvers[-3:]
                        facts['go_binaries'][name] = info
                    elif m.mode & 0o111 and b'GNU C Library' in data and elf_info(data)['static']:
                        facts['elf_static_glibc'][name] = {'comment': elf_info(data)['comment'],
                                                           'sha256': sha256_bytes(data)}
    finally:
        proc.stdout.close()
        rc = proc.wait()
    if rc:
        raise RuntimeError(f'docker export {cid} exited {rc}')
    return facts


def inventory(candidates, arch, cache_dir: Path, workroot: Path, *, pull=True, expected_id=None,
              go_bin='go'):
    """Return the facts for one image platform (cached by image ID)."""
    ref, data = resolve_image(candidates, arch, pull=pull, expected_id=expected_id)
    if not ref:
        return None
    image_id = data['Id']
    cache = cache_dir / 'facts' / f'{image_id.replace(":", "_")}-{arch}.json'
    if cache.exists():
        facts = json.loads(cache.read_text())
        if facts.get('facts_version') == FACTS_VERSION:
            facts['resolved_ref'] = ref
            if facts.get('rpmdb_dir') and not Path(facts['rpmdb_dir']).exists():
                pass
            else:
                return facts
    name = f'krate-collect-sources-{uuid.uuid4().hex[:12]}'
    workdir = workroot / f'{image_id.replace(":", "_")}-{arch}'
    workdir.mkdir(parents=True, exist_ok=True)
    log(f'exporting {ref} linux/{arch} ({image_id[:19]})')
    run('docker', 'create', '--platform', f'linux/{arch}', '--name', name, ref, '/krate-collect-sources-noop')
    try:
        facts = scan_container(name, workdir, go_bin=go_bin)
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    hist = subprocess.run(['docker', 'history', '--platform', f'linux/{arch}', '--no-trunc',
                           '--format', '{{.CreatedBy}}', ref], capture_output=True, text=True)
    if hist.returncode:  # older CLIs have no --platform on history
        hist = subprocess.run(['docker', 'history', '--no-trunc', '--format', '{{.CreatedBy}}', ref],
                              capture_output=True, text=True)
    facts['history'] = hist.stdout.splitlines()[::-1]
    facts.update({'facts_version': FACTS_VERSION, 'image_id': image_id, 'arch': arch,
                  'resolved_ref': ref, 'repo_digests': data.get('RepoDigests') or [],
                  'labels': (data.get('Config') or {}).get('Labels') or {},
                  'created': data.get('Created'), 'os': data.get('Os'),
                  'variant': data.get('Variant')})
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(facts))
    return facts
