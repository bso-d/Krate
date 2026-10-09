"""JavaScript packages bundled into web front ends (Grafana, Perses, Kafbat UI).

A bundled front end keeps no package list, so the production dependency closure is
computed from the project's lockfile at the exact commit the image was built from:
  * package-lock.json (npm): entries without "dev": true;
  * pnpm-lock.yaml v9: closure of the root importer's `dependencies`;
  * yarn.lock (berry): closure of every workspace package.json's `dependencies`.
This can include packages that are installed but tree-shaken out of the bundle, so it is
a superset. Licences come from deps.dev (fallback: the registry's version document);
copyleft tarballs are downloaded from registry.npmjs.org and verified against the
registry's `dist.integrity` (SHA-512)."""
from __future__ import annotations

import base64
import json
import re

import depsdev
from common import (Component, Unresolved, classify_expression, quote_url, slug)
import gitsrc

REGISTRY = 'https://registry.npmjs.org'


def frontends(facts, image_ref):
    """Detect bundled front ends: (repo, revision, how, lockfile kind, lockfile path)."""
    labels = facts.get('labels') or {}
    out = []
    for path, info in (facts.get('go_binaries') or {}).items():
        main = (info.get('main') or {}).get('path') or ''
        src = labels.get('org.opencontainers.image.source', '')
        if main == 'github.com/grafana/grafana' and path.endswith('/grafana'):
            tag = image_ref.split('@', 1)[0].rsplit(':', 1)[-1]
            out.append(('https://github.com/grafana/grafana', 'v' + tag.lstrip('v'), 'image tag', 'yarn', 'yarn.lock'))
        if src == 'https://github.com/perses/perses' and path.endswith('bin/perses'):
            rev = labels.get('org.opencontainers.image.revision')
            if rev:
                out.append((src, rev, 'image label org.opencontainers.image.revision', 'npm', 'ui/package-lock.json'))
    for jar in facts.get('jars') or []:
        if jar['path'].rsplit('/', 1)[-1] == 'api.jar' and any('kafbat' in (m.get('groupId') or '') or
                                                                 'kafbat' in (m.get('artifactId') or '')
                                                                 for m in jar.get('maven') or []) or \
                jar['path'] == 'api.jar':
            rev = labels.get('io.krate.kafbat-source-revision')
            how = 'image label io.krate.kafbat-source-revision'
            if not rev:
                tag = image_ref.split('@', 1)[0].rsplit(':', 1)[-1]
                rev, how = tag, 'image tag'
            out.append(('https://github.com/kafbat/kafka-ui', rev, how, 'pnpm', 'frontend/pnpm-lock.yaml'))
    return out


def components(facts, image_ref, arch, cache, registry):
    n = 0
    for repo, rev, how, kind, lock in frontends(facts, image_ref):
        key = f'npmfrontend:{repo}@{rev}'
        comp = registry.get(key)
        if comp is None:
            comp = Component(key=key, ecosystem='npm-frontend', name=repo, version=rev,
                             licence='(front-end dependency closure, see npm components)',
                             category='permissive', families=[])
            comp.fetch = {'repo': repo, 'rev': rev, 'how': how, 'kind': kind, 'lock': lock}
            registry[key] = comp
        comp.add_image(image_ref, arch, f'bundled front end ({kind} lockfile {lock} at {rev}, {how})')
        n += 1
    return n


# ---------------------------------------------------------------- lockfile parsers

def parse_package_lock(text):
    data = json.loads(text)
    out = set()
    for path, meta in (data.get('packages') or {}).items():
        if 'node_modules/' not in path or meta.get('link') or meta.get('dev'):
            continue
        name = meta.get('name') or path.rsplit('node_modules/', 1)[-1]
        if meta.get('version'):
            out.add((name, meta['version']))
    return out


def _yaml_blocks(text, section):
    """Return {key: [child lines]} for the top-level `section:` of a pnpm lockfile."""
    m = re.search(rf'^{section}:\n(.*?)(?=^\S|\Z)', text, re.S | re.M)
    if not m:
        return {}
    blocks, cur = {}, None
    for line in m.group(1).splitlines():
        if re.match(r'^  \S', line):
            cur = line.strip().rstrip(':').rstrip(' {}').rstrip(':').strip("'\"")
            blocks[cur] = []
        elif cur is not None and line.strip():
            blocks[cur].append(line)
    return blocks


def _pnpm_deps(lines, groups=('dependencies', 'optionalDependencies')):
    deps, group = [], None
    for line in lines:
        m = re.match(r'^(\s+)(\S.*?):\s*(.*)$', line)
        if not m:
            continue
        indent, k, v = len(m.group(1)), m.group(2).strip("'\""), m.group(3).strip().strip("'\"")
        if indent == 4:
            group = k
        elif indent == 6 and group in groups and v:
            deps.append((k, v))
        elif indent == 6 and group in groups and not v:
            deps.append((k, None))  # importer form: name: {specifier, version}
        elif indent == 8 and group in groups and k == 'version' and deps and deps[-1][1] is None:
            deps[-1] = (deps[-1][0], v)
    return deps


def parse_pnpm(text):
    importers = _yaml_blocks(text, 'importers')
    snaps = _yaml_blocks(text, 'snapshots')
    roots = _pnpm_deps(importers.get('.', []), groups=('dependencies', 'optionalDependencies'))
    out, todo, seen = set(), list(roots), set()
    while todo:
        name, ver = todo.pop()
        if not ver or ver.startswith(('link:', 'file:')):
            continue
        # An alias ("npm:other@1.0.0" style) names the package itself; a version starts with a digit.
        key = ver if not re.match(r'^\d', ver) and '@' in ver else f'{name}@{ver}'
        if key in seen:
            continue
        seen.add(key)
        base = re.sub(r'\(.*$', '', key)
        pname, pver = base.rsplit('@', 1)
        out.add((pname, pver))
        todo += _pnpm_deps(snaps.get(key, []), groups=('dependencies', 'optionalDependencies'))
    return out


def parse_berry(text):
    entries, by_desc = [], {}
    cur = None
    for line in text.splitlines():
        if line and not line.startswith(' ') and line.endswith(':') and not line.startswith('__metadata'):
            descs = [d.strip().strip('"') for d in line[:-1].strip('"').split(', ')]
            cur = {'descs': descs, 'deps': [], 'version': None, 'resolution': None, 'section': None}
            entries.append(cur)
            for d in descs:
                by_desc[d] = cur
        elif cur is not None and line.startswith('  ') and not line.startswith('    '):
            k, _, v = line.strip().partition(':')
            cur['section'] = k
            if k == 'version':
                cur['version'] = v.strip()
            elif k == 'resolution':
                cur['resolution'] = v.strip().strip('"')
        elif cur is not None and line.startswith('    ') and cur['section'] == 'dependencies':
            k, _, v = line.strip().partition(': ')
            cur['deps'].append((k.strip('"'), v.strip().strip('"')))
    return entries, by_desc


def berry_closure(entries, by_desc, roots):
    out, todo, seen = set(), list(roots), set()
    while todo:
        name, rng = todo.pop()
        desc = f'{name}@{rng}' if ':' in rng else f'{name}@npm:{rng}'
        e = by_desc.get(desc)
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        res = e['resolution'] or ''
        if '@workspace:' in res:
            continue  # workspace packages are part of the project's own source
        m = re.match(r'^(@?[^@]+)@(?:npm:|patch:.*?npm%3A)([^#\s]+)', res)
        if m:
            out.add((m.group(1), m.group(2).replace('%3A', ':')))
        todo += e['deps']
    return out


def closure_for(cache, fe):
    repo, rev, kind, lock = fe['repo'], fe['rev'], fe['kind'], fe['lock']
    commit = gitsrc.resolve(cache, repo, rev)
    owner = repo.split('github.com/', 1)[1]
    raw = f'https://raw.githubusercontent.com/{owner}/{commit}'
    text = cache.cached_get(f'{raw}/{lock}', allow_404=True)
    if not text:
        raise Unresolved(f'{lock} not found at {repo}@{commit}')
    text = text.decode('utf-8', 'replace')
    if kind == 'npm':
        return commit, parse_package_lock(text)
    if kind == 'pnpm':
        return commit, parse_pnpm(text)
    entries, by_desc = parse_berry(text)
    roots = []
    for e in entries:
        res = e['resolution'] or ''
        m = re.match(r'^(@?[^@]+)@workspace:(.*)$', res)
        if not m:
            continue
        wpath = m.group(2)
        pj = cache.cached_get(f'{raw}/{"" if wpath == "." else wpath + "/"}package.json', allow_404=True)
        if not pj:
            continue
        prod = set(json.loads(pj).get('dependencies') or {}) | set(json.loads(pj).get('optionalDependencies') or {})
        roots += [(n, r) for n, r in e['deps'] if n in prod]
    return commit, berry_closure(entries, by_desc, roots)


def classify(comps_or_registry, cache):
    registry = comps_or_registry if isinstance(comps_or_registry, dict) else None
    if registry is None:
        return
    fes = [c for c in list(registry.values()) if c.ecosystem == 'npm-frontend']
    for fe in fes:
        try:
            commit, pkgs = closure_for(cache, fe.fetch)
        except Exception as exc:  # recorded as UNRESOLVED, never fatal
            fe.category, fe.licence = 'unknown', f'front-end dependency list unavailable: {exc}'
            fe.fetch['unresolved'] = str(exc)
            continue
        fe.notes.append(f'{len(pkgs)} production packages from {fe.fetch["lock"]} at {commit}')
        for name, ver in sorted(pkgs):
            key = f'npm:{name}@{ver}'
            comp = registry.get(key)
            if comp is None:
                comp = Component(key=key, ecosystem='npm', name=name, version=ver, licence='',
                                 category='unknown', families=[])
                registry[key] = comp
            for img, arches in fe.images.items():
                for a in arches:
                    comp.add_image(img, a, f'{fe.fetch["repo"]} front end, {fe.fetch["lock"]}@{commit[:12]}')
    todo = [c for c in registry.values() if c.ecosystem == 'npm' and not c.licence]
    found = depsdev.licences(cache, 'NPM', [(c.name, c.version) for c in todo])
    for c in todo:
        lic = found.get((c.name, c.version))
        source = 'deps.dev'
        if not lic or lic == ['non-standard']:
            doc = cache.cached_json(f'{REGISTRY}/{quote_url(c.name).replace("%40", "@")}/{c.version}', allow_404=True) or {}
            l = doc.get('license')
            if isinstance(l, dict):
                l = l.get('type')
            lic = [l] if isinstance(l, str) and l else None
            source = 'registry.npmjs.org version document'
        if not lic:
            c.licence, c.category = 'undeclared', 'unknown'
            continue
        exprs = [classify_expression(x) for x in lic]
        c.licence = ' AND '.join(lic)
        c.category = ('copyleft' if any(e['category'] == 'copyleft' for e in exprs) else
                      'elected-permissive' if any(e['category'] == 'elected-permissive' for e in exprs) else
                      'unknown' if all(e['category'] == 'unknown' for e in exprs) else 'permissive')
        c.families = sorted({f for e in exprs for f in e['families']})
        c.notes.append(f'licence from {source}; listed in a production lockfile closure (may be tree-shaken)')


def fetch(comp, cache, out_dir, rel_root, workroot=None):
    if comp.ecosystem == 'npm-frontend':
        raise Unresolved(comp.fetch.get('unresolved') or 'front end without dependency list')
    doc = cache.cached_json(f'{REGISTRY}/{quote_url(comp.name).replace("%40", "@")}/{comp.version}', allow_404=True)
    if not doc or 'dist' not in doc:
        raise Unresolved(f'registry.npmjs.org has no {comp.name}@{comp.version}')
    integ = doc['dist'].get('integrity', '')
    if integ.startswith('sha512-'):
        algo, digest = 'sha512', base64.b64decode(integ[7:]).hex()
    else:
        algo, digest = 'sha1', doc['dist']['shasum']
    path, got = cache.fetch([doc['dist']['tarball']], algo, digest)
    fname = doc['dist']['tarball'].rsplit('/', 1)[-1]
    return [(path, f'{rel_root}/npm/{slug(comp.name)}/{comp.version}/{fname}', got,
             f'{algo} from registry.npmjs.org dist.integrity')]
