"""Python distributions installed with pip (not by rpm/dpkg) and the libraries pip
vendors (pip/_vendor/vendor.txt). Copyleft ones get their sdist from PyPI, verified
against the SHA-256 PyPI publishes for that file."""
from __future__ import annotations

import re

import depsdev
from common import Component, Unresolved, classify_expression, classify_texts, slug


def parse_metadata(text):
    head = text.split('\n\n', 1)[0]
    fields = {}
    for line in head.splitlines():
        if ':' in line and not line.startswith((' ', '\t')):
            k, v = line.split(':', 1)
            fields.setdefault(k.strip(), []).append(v.strip())
    return fields


def classify_metadata(fields):
    expr = (fields.get('License-Expression') or [''])[0]
    if expr:
        r = classify_expression(expr)
        return expr, r['category'], r['families']
    texts = [c for c in fields.get('Classifier', []) if c.startswith('License ::')]
    lic = (fields.get('License') or [''])[0]
    if lic and len(lic) < 200:
        texts.append(lic)
    r = classify_texts(texts)
    return ' | '.join(texts) or 'undeclared', r['category'], r['families']


def components(facts, image_ref, arch, cache, registry):
    n = 0
    installers = facts.get('python_installer') or {}
    for path, text in sorted((facts.get('python') or {}).items()):
        inst = installers.get(path.rsplit('/', 1)[0] + '/INSTALLER', '')
        if inst in ('rpm', 'dpkg', 'debian', 'apk'):
            continue  # the distribution package's source covers it
        if inst != 'pip' and not path.startswith(('usr/local/', 'opt/')):
            continue  # system site-packages without a pip INSTALLER belong to an rpm/dpkg package
        fields = parse_metadata(text)
        name, ver = (fields.get('Name') or [''])[0], (fields.get('Version') or [''])[0]
        if not name:
            continue
        key = f'pypi:{name.lower()}@{ver}'
        comp = registry.get(key)
        if comp is None:
            lic, cat, fams = classify_metadata(fields)
            comp = Component(key=key, ecosystem='pypi', name=name, version=ver, licence=lic,
                             category=cat, families=fams)
            comp.notes.append(f'installed by {inst or "unknown installer"}; licence from package METADATA')
            registry[key] = comp
        comp.add_image(image_ref, arch, path)
        n += 1
    vendored = []
    for path, text in sorted((facts.get('pip_vendor') or {}).items()):
        for line in text.splitlines():
            m = re.match(r'^\s*([A-Za-z0-9_.\-]+)==([^\s;#]+)', line)
            if m:
                vendored.append((m.group(1), m.group(2), path))
    found = depsdev.licences(cache, 'PYPI', [(n_.lower(), v) for n_, v, _ in vendored])
    for name, ver, path in vendored:
        key = f'pypi:{name.lower()}@{ver}'
        comp = registry.get(key)
        if comp is None:
            lic = found.get((name.lower(), ver)) or []
            exprs = [classify_expression(l) for l in lic]
            cat = ('copyleft' if any(e['category'] == 'copyleft' for e in exprs) else
                   'elected-permissive' if any(e['category'] == 'elected-permissive' for e in exprs) else
                   'permissive' if lic else 'unknown')
            comp = Component(key=key, ecosystem='pypi', name=name, version=ver,
                             licence=' AND '.join(lic) or 'unknown', category=cat,
                             families=sorted({f for e in exprs for f in e['families']}))
            comp.notes.append(f'vendored inside pip ({path}); licence from deps.dev')
            registry[key] = comp
        comp.add_image(image_ref, arch, f'{path} (vendored)')
        n += 1
    return n


def fetch(comp, cache, out_dir, rel_root):
    data = cache.cached_json(f'https://pypi.org/pypi/{comp.name}/{comp.version}/json', allow_404=True)
    if not data:
        raise Unresolved(f'PyPI has no release {comp.name} {comp.version}')
    urls = data.get('urls') or []
    pick = [u for u in urls if u['packagetype'] == 'sdist'] or \
        [u for u in urls if u['packagetype'] == 'bdist_wheel' and u['filename'].endswith('-none-any.whl')]
    if not pick:
        raise Unresolved(f'PyPI {comp.name} {comp.version} has no sdist or pure-Python wheel')
    u = pick[0]
    path, got = cache.fetch([u['url']], 'sha256', u['digests']['sha256'], size=u.get('size'))
    if u['packagetype'] != 'sdist':
        comp.notes.append('no sdist on PyPI; the pure-Python wheel is the source form')
    return [(path, f'{rel_root}/pypi/{slug(comp.name)}/{comp.version}/{u["filename"]}', got,
             'sha256 from PyPI JSON API digests')]
