"""Java libraries (JAR files, including Spring Boot nested JARs) -> Maven sources JARs.

Coordinates come from META-INF/maven/**/pom.properties, or, when a JAR has none, from
Maven Central's SHA-1 search for the exact JAR bytes. Licences come from deps.dev (which
reads the published POM), then the embedded/Central POM and its parents, then licence
files inside the JAR. Copyleft (or unclassifiable) artifacts get their
`-sources.jar` from the repository that published them, verified against the
repository's published checksum file; the shipped JAR's SHA-1 is also compared with the
repository's checksum of the binary to confirm the exact version."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import depsdev
from common import (Component, Unresolved, classify_texts, log, quote_url, slug)

REPOS = [
    ('maven-central', 'https://repo1.maven.org/maven2'),
    ('confluent', 'https://packages.confluent.io/maven'),
    ('redhat-ga', 'https://maven.repository.redhat.com/ga'),
]
SEARCH = 'https://central.sonatype.com/solrsearch/select?wt=json&rows=5&q=1:{sha1}'
DEPSDEV_HASH = 'https://api.deps.dev/v3alpha/query?hash.type=SHA1&hash.value={b64}'


def walk_jars(jars):
    for j in jars:
        yield j
        yield from walk_jars(j.get('nested') or [])


def _pom_licences(pom_text):
    """(licence names/urls, parent gav) from a POM document."""
    try:
        root = ET.fromstring(re.sub(r'\sxmlns="[^"]+"', '', pom_text, count=1))
    except ET.ParseError:
        return [], None
    names = []
    for lic in root.findall('./licenses/license'):
        name = (lic.findtext('name') or '').strip()
        url = (lic.findtext('url') or '').strip()
        names.append(f'{name} <{url}>' if url else name)
    parent = root.find('parent')
    pgav = None
    if parent is not None:
        pgav = (parent.findtext('groupId'), parent.findtext('artifactId'), parent.findtext('version'))
    return names, pgav


def _repo_path(g, a, v):
    return f'{g.replace(".", "/")}/{a}/{v}'


def pom_chain_licences(cache, g, a, v, pom_text=None, depth=0):
    if depth > 8:
        return [], None
    if pom_text is None:
        for _name, base in REPOS:
            data = cache.cached_get(f'{base}/{_repo_path(g, a, v)}/{a}-{v}.pom', allow_404=True)
            if data:
                pom_text = data.decode('utf-8', 'replace')
                break
    if not pom_text:
        return [], None
    names, parent = _pom_licences(pom_text)
    if names:
        return names, f'POM {g}:{a}:{v}' + (' (inherited)' if depth else '')
    if parent and all(parent) and '${' not in ''.join(parent):
        return pom_chain_licences(cache, *parent, depth=depth + 1)
    return [], None


def identify_by_sha1(cache, sha1):
    """Exact-bytes lookup: deps.dev hash index of Maven Central, then Central's own search."""
    import base64
    try:
        data = cache.cached_json(DEPSDEV_HASH.format(b64=quote_url(base64.b64encode(bytes.fromhex(sha1)).decode())),
                                 allow_404=True, timeout=30)
        hits = [r['version']['versionKey']['name'].split(':', 1) + [r['version']['versionKey']['version']]
                for r in (data or {}).get('results', []) if r['version']['versionKey']['system'] == 'MAVEN']
        if hits:
            return [tuple(h) for h in hits]
    except Exception as exc:
        log(f'deps.dev hash query failed for {sha1}: {exc}')
    try:
        data = cache.cached_json(SEARCH.format(sha1=sha1), allow_404=True, timeout=30)
    except Exception as exc:
        log(f'Central SHA-1 search failed for {sha1}: {exc}')
        return []
    docs = (data or {}).get('response', {}).get('docs', [])
    return [(d['g'], d['a'], d['v']) for d in docs]


SEARCH_A = 'https://central.sonatype.com/solrsearch/select?wt=json&rows=40&q=a:%22{a}%22'


def _pom_exists(cache, g, a, v):
    for repo_name, base in REPOS:
        try:
            if cache.cached_get(f'{base}/{_repo_path(g, a, v)}/{a}-{v}.pom', allow_404=True, timeout=30):
                return repo_name
        except Exception:
            continue
    return None


def identify_by_name(cache, filename, manifest):
    """Coordinates from the file name when the bytes match no published JAR (rebuilt or
    repackaged JARs). Handles `artifact-version.jar` and Keycloak/Quarkus
    `group.artifact-version.jar`; the coordinate must exist as a published POM."""
    stem = filename[:-4] if filename.endswith('.jar') else filename
    m = re.match(r'^(?P<a>.+?)-(?P<v>v?\d[\w.+\-]*)$', stem)
    if not m:
        return None
    a, v = m.group('a'), m.group('v')
    cands = []
    if '.' in a:  # group.artifact form: try every split point
        parts = a.split('.')
        for i in range(len(parts) - 1, 0, -1):
            cands.append(('.'.join(parts[:i]), '.'.join(parts[i:])))
    groups = set()
    for key in ('Implementation-Vendor-Id', 'Bundle-SymbolicName', 'Automatic-Module-Name'):
        val = (manifest or {}).get(key, '').split(';')[0].strip()
        if val:
            groups.add(val)
            if '.' in val:
                groups.add(val.rsplit('.', 1)[0])
    if a.startswith(('kafka', 'connect-', 'trogdor')):
        groups.add('org.apache.kafka')
    try:
        data = cache.cached_json(SEARCH_A.format(a=quote_url(a)), allow_404=True, timeout=30) or {}
        groups |= {d['g'] for d in data.get('response', {}).get('docs', [])}
    except Exception as exc:
        log(f'Central artifact search failed for {a}: {exc}')
    cands += [(g, a) for g in sorted(groups)]
    for g, art in cands:
        repo = _pom_exists(cache, g, art, v)
        if repo:
            return g, art, v, repo
    return None


def project_licence(facts, image_ref, cache):
    """Licence of the project the image ships (for its own, unpublished build outputs):
    the image's org.opencontainers.image.licenses label, else the LICENSE file of the
    project repository at the image's revision/tag."""
    labels = facts.get('labels') or {}
    if labels.get('org.opencontainers.image.licenses'):
        return labels['org.opencontainers.image.licenses'], 'image label org.opencontainers.image.licenses'
    import npm  # front-end detection also identifies the Kafbat project and revision
    for repo, rev, how, _kind, _lock in npm.frontends(facts, image_ref):
        owner = repo.split('github.com/', 1)[1]
        data = cache.cached_get(f'https://raw.githubusercontent.com/{owner}/{rev}/LICENSE', allow_404=True)
        if data:
            text = data[:20000].decode('utf-8', 'replace')
            name = 'Apache-2.0' if 'Apache License' in text and 'Version 2.0' in text else 'see LICENSE'
            return (name if name != 'see LICENSE' else text[:2000]), f'LICENSE of {repo} at {rev} ({how})'
    return None, None


def _version_of(name):
    m = re.search(r'-(v?\d[\w.+\-]*)\.jar$', name)
    return m.group(1).lstrip('v') if m else None


def components(facts, image_ref, arch, cache, registry):
    """Register every JAR coordinate; licences are resolved later in one batch."""
    count = 0
    for jar in walk_jars(facts.get('jars') or []):
        coords = [(m['groupId'], m['artifactId'], m['version'], m.get('pom') or '') for m in jar['maven']]
        how = 'pom.properties in the JAR'
        if not coords:
            hits = identify_by_sha1(cache, jar['sha1'])
            if hits:
                coords = [(g, a, v, '') for g, a, v in hits[:1]]
                how = 'Maven Central SHA-1 search for the exact JAR bytes'
        if not coords:
            hit = identify_by_name(cache, jar['path'].rsplit('/', 1)[-1], jar['manifest'])
            if hit:
                coords = [(hit[0], hit[1], hit[2], '')]
                how = (f'file name matched the published {hit[3]} coordinate; the JAR bytes match no '
                       'published artifact (rebuilt by the image vendor)')
        if not coords:
            if jar['path'].endswith('/jrt-fs.jar') or '/lib/jvm/' in jar['path'] or '/opt/java/' in jar['path']:
                continue  # part of the JDK, handled with the JDK component
            if jar['path'].count('!/') >= 2:
                continue  # a resource JAR inside an identified library JAR: part of that library
            name = jar['path'].rsplit('/', 1)[-1]
            key = f'jar:{name}@sha1:{jar["sha1"][:12]}'
            comp = registry.get(key)
            if comp is None:
                texts = list(jar['licence_files'].values()) + [jar['manifest'].get('Bundle-License', '')]
                cls = classify_texts(texts)
                tag = image_ref.split('@', 1)[0].rsplit(':', 1)[-1].lstrip('v').split('-')[0]
                jver = _version_of(name)
                own = cls['category'] == 'unknown' and (jver is None or jver.split('-')[0] == tag)
                plic, pwhere = project_licence(facts, image_ref, cache) if own else (None, None)
                comp = Component(key=key, ecosystem='jar', name=name, version=jar['manifest'].get(
                    'Implementation-Version') or jar['manifest'].get('Bundle-Version') or '',
                    licence=jar['manifest'].get('Bundle-License') or
                    ('licence files in JAR' if jar['licence_files'] else 'undeclared'),
                    category=cls['category'], families=cls['families'])
                comp.notes.append('no Maven coordinates (no pom.properties, no SHA-1 or name match in Maven '
                                  'Central, Confluent or Red Hat GA)')
                if plic:
                    pcls = classify_texts([plic])
                    comp.licence, comp.category, comp.families = plic[:200], pcls['category'], pcls['families']
                    comp.notes.append(f'treated as the image project\'s own build output (version matches the '
                                      f'image tag or is unversioned); licence from {pwhere}')
                comp.fetch = {'sha1': jar['sha1'], 'manifest': jar['manifest']}
                registry[key] = comp
            comp.add_image(image_ref, arch, jar['path'])
            count += 1
            continue
        primary = coords[0]
        if len(coords) > 1:
            stem = jar['path'].rsplit('/', 1)[-1]
            primary = next((c for c in coords if c[1] in stem and c[2] in stem), coords[0])
        for g, a, v, pom in coords:
            key = f'maven:{g}:{a}@{v}'
            comp = registry.get(key)
            if comp is None:
                comp = Component(key=key, ecosystem='maven', name=f'{g}:{a}', version=v, licence='',
                                 category='unknown', families=[])
                comp.fetch = {'g': g, 'a': a, 'v': v, 'pom': pom, 'sha1s': {}, 'how': how,
                              'jar_texts': []}
                registry[key] = comp
            if how.startswith('file name'):
                comp.notes.append(f'{jar["path"]}: {how}')
            if (g, a, v) == primary[:3]:
                comp.fetch['sha1s'][jar['sha1']] = jar['path']
            else:
                comp.notes.append(f'embedded (shaded) in {jar["path"].rsplit("/", 1)[-1]}')
            comp.fetch['jar_texts'] = list(jar['licence_files'].values())[:4] + \
                [jar['manifest'].get('Bundle-License', '')]
            comp.add_image(image_ref, arch, jar['path'])
            count += 1
    return count


def classify(comps, cache):
    """Resolve licences for all Maven components (deps.dev batch, then POM chain, then JAR)."""
    mvn = [c for c in comps if c.ecosystem == 'maven' and not c.licence]
    found = depsdev.licences(cache, 'MAVEN', [(f'{c.fetch["g"]}:{c.fetch["a"]}', c.fetch['v']) for c in mvn])
    for c in mvn:
        lic = found.get((f'{c.fetch["g"]}:{c.fetch["a"]}', c.fetch['v']))
        source = 'deps.dev (from the published POM)'
        names = list(lic or [])
        if not names or names == ['non-standard']:
            pom_names, where = pom_chain_licences(cache, c.fetch['g'], c.fetch['a'], c.fetch['v'],
                                                  c.fetch.get('pom') or None)
            if not pom_names and c.fetch.get('pom'):
                pom_names, where = pom_chain_licences(cache, c.fetch['g'], c.fetch['a'], c.fetch['v'])
            if pom_names:
                names, source = pom_names, where
        if not names:
            texts = [t for t in c.fetch.get('jar_texts', []) if t]
            if texts:
                cls = classify_texts(texts)
                c.licence = 'licence files inside the JAR'
                c.category, c.families = cls['category'], cls['families']
                c.notes.append('licence from files inside the JAR')
                continue
            c.licence = 'undeclared'
            c.category = 'unknown'
            continue
        cls = classify_texts(names)
        c.licence = ' | '.join(names)[:500]
        c.category, c.families = cls['category'], cls['families']
        if len(names) > 1 and cls['category'] == 'copyleft':
            c.notes.append('several licences listed; treated as copyleft (conservative)')
        c.notes.append(f'licence from {source}')


def _checksum(cache, url):
    for algo in ('sha512', 'sha256', 'sha1'):
        data = cache.cached_get(f'{url}.{algo}', allow_404=True)
        if data:
            m = re.search(rb'\b([0-9a-fA-F]{40,128})\b', data)
            if m:
                return algo, m.group(1).decode().lower()
    return None, None


def fetch(comp, cache, out_dir, rel_root):
    if comp.ecosystem == 'jar':
        raise Unresolved('JAR has no Maven coordinates and no Central SHA-1 match, so its exact '
                         'source cannot be located from an authoritative repository')
    g, a, v = comp.fetch['g'], comp.fetch['a'], comp.fetch['v']
    files = []
    for repo_name, base in REPOS:
        url = f'{base}/{_repo_path(g, a, v)}/{a}-{v}-sources.jar'
        algo, digest = _checksum(cache, url)
        if not digest:
            continue
        path, got = cache.fetch([url], algo, digest)
        files.append((path, f'{rel_root}/maven/{slug(g)}/{slug(a)}/{v}/{a}-{v}-sources.jar', got,
                      f'{algo} from {repo_name} checksum file {url}.{algo}'))
        # Confirm the shipped binary is this exact published artifact.
        bin_sha1 = None
        data = cache.cached_get(f'{base}/{_repo_path(g, a, v)}/{a}-{v}.jar.sha1', allow_404=True)
        if data:
            m = re.search(rb'\b([0-9a-fA-F]{40})\b', data)
            bin_sha1 = m.group(1).decode().lower() if m else None
        shipped = comp.fetch.get('sha1s') or {}
        if shipped and bin_sha1:
            if bin_sha1 in shipped:
                comp.notes.append(f'shipped JAR SHA-1 {bin_sha1} = {repo_name} {a}-{v}.jar')
            else:
                comp.notes.append(f'shipped JAR SHA-1 {sorted(shipped)} differs from {repo_name} '
                                  f'{a}-{v}.jar ({bin_sha1}): rebuilt or repackaged binary')
        pom_url = f'{base}/{_repo_path(g, a, v)}/{a}-{v}.pom'
        palgo, pdigest = _checksum(cache, pom_url)
        if pdigest:
            ppath, pgot = cache.fetch([pom_url], palgo, pdigest)
            files.append((ppath, f'{rel_root}/maven/{slug(g)}/{slug(a)}/{v}/{a}-{v}.pom', pgot,
                          f'{palgo} from {repo_name} checksum file'))
        return files
    raise Unresolved(f'no {a}-{v}-sources.jar on Maven Central, Confluent or Red Hat GA repositories')
