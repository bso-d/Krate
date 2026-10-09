"""Go binaries: build information (`go version -m`) -> module zips and main-module source.

* Dependencies: licences from deps.dev (fallback: the licence files of the module zip).
  Copyleft modules are fetched with `go mod download`, which verifies every zip against
  the Go checksum database (sum.golang.org); the h1: hash is also compared with the one
  embedded in the binary when the binary records it.
* Main module: its licence is read from the repository at the exact revision; when it is
  copyleft (Grafana, Loki: AGPL-3.0) the source is a `git archive` of that commit,
  fetched by commit id (git verifies every object against the id).
* Static glibc (cgo + static link): the application source is shipped for relinking
  (LGPL-2.1 section 6) and the Debian glibc sources are added by the Debian handler."""
from __future__ import annotations

import json
import os
import re
import subprocess
import zipfile
from pathlib import Path

import depsdev
from common import (Component, Unresolved, VerificationError, classify_texts, log, slug)
import gitsrc

LICENCE_FILE = re.compile(r'(^|/)(LICEN[CS]E|COPYING|UNLICENSE)[^/]*$', re.I)


def module_of(dep):
    rep = dep.get('replace')
    if rep and rep.get('version'):
        return rep['path'], rep['version'], rep.get('sum') or ''
    if rep and not rep.get('version'):
        return None  # replaced by a local directory: part of the main module's source
    return dep['path'], dep['version'], dep.get('sum') or ''


def github_repo(module_path):
    m = re.match(r'^github\.com/([^/]+)/([^/]+)', module_path)
    return f'https://github.com/{m.group(1)}/{m.group(2)}' if m else None


def main_revision(binfo, labels, image_ref):
    """Best evidence for the main module's commit/tag, with how it was found."""
    b = binfo['build']
    if b.get('vcs.revision'):
        return b['vcs.revision'], 'vcs.revision in Go build info'
    m = re.search(r'\.Revision=([0-9a-f]{12,40})\b', b.get('-ldflags', ''))
    if m:
        return m.group(1), '-X ...Revision in Go build -ldflags'
    ver = (binfo.get('main') or {}).get('version') or ''
    m = re.search(r'-([0-9a-f]{12})(\+dirty)?$', ver)
    if m:
        return m.group(1), 'pseudo-version of the main module'
    if re.fullmatch(r'v\d+\.\d+\.\d+.*', ver):
        return ver, 'main module version (tag)'
    if labels.get('org.opencontainers.image.revision'):
        return labels['org.opencontainers.image.revision'], 'image label org.opencontainers.image.revision'
    for key in ('org.opencontainers.image.version', 'version'):
        if labels.get(key):
            v = labels[key]
            return (v if v.startswith('v') else 'v' + v), f'image label {key} (tag)'
    tag = image_ref.split('@', 1)[0].rsplit(':', 1)[-1] if ':' in image_ref.split('@', 1)[0] else ''
    if re.fullmatch(r'v?\d+\.\d+\.\d+', tag):
        return (tag if tag.startswith('v') else 'v' + tag), 'image tag (tag)'
    return None, 'no revision evidence'


def components(facts, image_ref, arch, cache, registry):
    n = 0
    for path, info in sorted((facts.get('go_binaries') or {}).items()):
        if not info.get('path') and not info.get('main'):
            continue
        for dep in info['deps']:
            mod = module_of(dep)
            if not mod:
                continue
            mpath, mver, msum = mod
            if mver in ('(devel)', ''):
                continue  # the project's own module: covered by the main-module component
            key = f'go:{mpath}@{mver}'
            comp = registry.get(key)
            if comp is None:
                comp = Component(key=key, ecosystem='go', name=mpath, version=mver, licence='',
                                 category='unknown', families=[])
                comp.fetch = {'sums': set()}
                registry[key] = comp
            if msum:
                comp.fetch['sums'].add(msum)
            comp.add_image(image_ref, arch, f'{path} ({info.get("go")})')
            n += 1
        main = info.get('main') or {'path': info.get('path'), 'version': ''}
        repo = github_repo(main['path'] or '') or \
            github_repo((facts.get('labels') or {}).get('org.opencontainers.image.source', '').replace('https://', ''))
        if main['path'] in (None, '', 'command-line-arguments') and repo:
            main = {'path': repo.replace('https://', ''), 'version': ''}
        rev, how = main_revision(info, facts.get('labels') or {}, image_ref)
        key = f'gomain:{main["path"]}@{rev}'
        comp = registry.get(key)
        if comp is None:
            comp = Component(key=key, ecosystem='git', name=main['path'], version=rev or '(unknown)',
                             licence='', category='unknown', families=[])
            comp.fetch = {'repo': repo, 'rev': rev, 'how': how, 'binaries': {}, 'relink': False}
            registry[key] = comp
        comp.fetch['binaries'][f'{image_ref}:{path}:{arch}'] = info['sha256']
        if info.get('static_glibc'):
            comp.fetch['relink'] = True
            facts.setdefault('_static_glibc', []).append((path, info))
        comp.add_image(image_ref, arch, f'{path} main module ({how})')
        n += 1
    return n


def _go_env(cache):
    root = Path(cache.root)
    env = dict(os.environ, GOMODCACHE=str(root / 'gomod'), GOPATH=str(root / 'gopath'),
               GOFLAGS='-mod=mod', GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org',
               GONOSUMDB='', GOPRIVATE='', GONOSUMCHECK='', GOINSECURE='', GOTOOLCHAIN='local',
               GO111MODULE='on')
    return env


def go_download(cache, mods, workdir: Path):
    """`go mod download -json` for module@version strings; returns {mod@ver: json}."""
    out = {}
    workdir.mkdir(parents=True, exist_ok=True)
    for i in range(0, len(mods), 50):
        chunk = mods[i:i + 50]
        proc = subprocess.run(['go', 'mod', 'download', '-json', *chunk], capture_output=True, text=True,
                              env=_go_env(cache), cwd=workdir)
        dec, text, pos = json.JSONDecoder(), proc.stdout, 0
        while True:
            while pos < len(text) and text[pos].isspace():
                pos += 1
            if pos >= len(text):
                break
            obj, pos = dec.raw_decode(text, pos)
            out[f'{obj.get("Path")}@{obj.get("Version")}'] = obj
    return out


def classify(comps, cache, workroot):
    deps = [c for c in comps if c.ecosystem == 'go' and not c.licence]
    found = depsdev.licences(cache, 'GO', [(c.name, c.version) for c in deps])
    fallback = []
    for c in deps:
        lic = found.get((c.name, c.version))
        if lic and lic != ['non-standard']:
            cls = classify_texts([' AND '.join(lic)])
            # deps.dev returns SPDX expressions; reuse the expression classifier for OR.
            from common import classify_expression
            exprs = [classify_expression(l) for l in lic]
            cat = ('copyleft' if any(e['category'] == 'copyleft' for e in exprs) else
                   'elected-permissive' if any(e['category'] == 'elected-permissive' for e in exprs)
                   else cls['category'])
            c.licence, c.category = ' AND '.join(lic), cat
            c.families = sorted({f for e in exprs for f in e['families']})
            c.notes.append('licence from deps.dev')
        else:
            fallback.append(c)
    if fallback:
        log(f'classifying {len(fallback)} Go modules from their verified module zips')
        got = go_download(cache, [f'{c.name}@{c.version}' for c in fallback], workroot / 'go-dl')
        for c in fallback:
            info = got.get(f'{c.name}@{c.version}') or {}
            if not info.get('Zip'):
                c.licence, c.category = 'module zip unavailable', 'unknown'
                c.notes.append(f'go mod download: {info.get("Error", "no result")}')
                continue
            texts = []
            with zipfile.ZipFile(info['Zip']) as z:
                for name in z.namelist():
                    if LICENCE_FILE.search(name) and '/testdata/' not in name and '/vendor/' not in name:
                        texts.append(z.read(name)[:20000].decode('utf-8', 'replace'))
            cls = classify_texts(texts)
            c.licence = 'licence files in module zip' if texts else 'no licence file'
            c.category, c.families = cls['category'], cls['families']
            c.notes.append('licence classified from licence files in the sumdb-verified module zip')
    for c in comps:
        if c.ecosystem != 'git' or c.licence or not c.key.startswith('gomain:'):
            continue
        repo, rev = c.fetch.get('repo'), c.fetch.get('rev')
        if not repo or not rev:
            c.licence, c.category = 'unknown (no repository/revision evidence)', 'unknown'
            continue
        try:
            commit = gitsrc.resolve(cache, repo, rev)
        except Unresolved as exc:
            c.licence, c.category = f'unknown ({exc})', 'unknown'
            continue
        c.fetch['commit'] = commit
        texts = []
        owner_repo = repo.split('github.com/', 1)[1]
        for name in ('LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING'):
            data = cache.cached_get(f'https://raw.githubusercontent.com/{owner_repo}/{commit}/{name}',
                                    allow_404=True)
            if data:
                texts.append(data[:40000].decode('utf-8', 'replace'))
                break
        cls = classify_texts(texts)
        c.licence = (('AGPL-3.0' if 'AGPL' in cls['families'] else
                      ', '.join(cls['families']) or 'permissive') + f' (LICENSE at {commit[:12]})')
        c.category, c.families = cls['category'], cls['families']
        if c.fetch.get('relink') and c.category != 'copyleft':
            c.category = 'copyleft'
            c.notes.append('application is not copyleft itself, but statically links LGPL glibc: '
                           'its complete source is shipped so users can relink (LGPL-2.1 section 6)')
            c.families = sorted(set(c.families) | {'LGPL-relink'})


def fetch(comp, cache, out_dir, rel_root, workroot):
    if comp.ecosystem == 'git':
        commit = comp.fetch.get('commit')
        if not commit:
            raise Unresolved(f'no commit for {comp.name}: {comp.licence}')
        path, desc = gitsrc.archive(cache, comp.fetch['repo'], commit, workroot)
        name = comp.fetch['repo'].rstrip('/').rsplit('/', 1)[-1]
        comp.notes.append(f'revision evidence: {comp.fetch.get("how")}; commit {commit}')
        return [(path, f'{rel_root}/git/{slug(name)}-{commit[:12]}.tar.gz',
                 f'{comp.fetch["repo"]}@{commit}', desc)]
    got = go_download(cache, [f'{comp.name}@{comp.version}'], workroot / 'go-dl')
    info = got.get(f'{comp.name}@{comp.version}') or {}
    if not info.get('Zip'):
        raise Unresolved(f'go mod download failed: {info.get("Error", "no result")}')
    for s in comp.fetch.get('sums') or ():
        if s and s != info.get('Sum'):
            raise VerificationError(f'binary records {s}, module proxy/sumdb gives {info.get("Sum")}')
    how = f'go mod download: {info.get("Sum")} verified against sum.golang.org'
    if comp.fetch.get('sums'):
        how += ' and equal to the h1: hash embedded in the binary'
    files = []
    esc = slug(comp.name.replace('/', '_'))
    for k, ext in (('Zip', '.zip'), ('GoMod', '.mod'), ('Info', '.info')):
        if info.get(k):
            files.append((Path(info[k]), f'{rel_root}/go/{esc}/{comp.version}/{comp.version}{ext}',
                          f'https://proxy.golang.org/{comp.name.lower()}/@v/{comp.version}{ext}', how))
    return files
