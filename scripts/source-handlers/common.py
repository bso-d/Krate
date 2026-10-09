"""Shared helpers for scripts/collect-sources.py: HTTP with a verified download cache,
hashing, licence classification and the component record written to the manifest."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

USER_AGENT = 'krate-collect-sources/1 (+https://github.com/; corresponding-source collector)'


class VerificationError(Exception):
    """A downloaded file did not match the hash published by its authoritative source."""


class Unresolved(Exception):
    """Corresponding source could not be obtained; the reason goes in the manifest."""


def log(*parts):
    print('collect-sources:', *parts, file=sys.stderr, flush=True)


def sha256_file(path, algo='sha256'):
    h = hashlib.new(algo)
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data, algo='sha256'):
    return hashlib.new(algo, data).hexdigest()


def run(*cmd, capture=True, check=True, env=None, input=None, cwd=None):
    proc = subprocess.run([str(c) for c in cmd], capture_output=capture, text=True, env=env,
                          input=input, cwd=cwd)
    if check and proc.returncode:
        raise RuntimeError(f'{" ".join(map(str, cmd))} failed ({proc.returncode}): '
                           f'{(proc.stderr or "").strip()[-2000:]}')
    return proc.stdout.strip() if capture else ''


def _open(url, timeout=120, headers=None):
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, **(headers or {})})
    return urllib.request.urlopen(req, timeout=timeout)


def http_get(url, *, retries=4, timeout=120, headers=None, allow_404=False):
    """GET a small document into memory. Returns None on 404 when allow_404."""
    delay = 2
    for attempt in range(retries):
        try:
            with _open(url, timeout, headers) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410) and allow_404:
                return None
            if exc.code in (404, 410, 401, 403) or attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            if attempt == retries - 1:
                raise
        time.sleep(delay)
        delay *= 2
    raise RuntimeError('unreachable')


def http_json(url, **kw):
    data = http_get(url, **kw)
    return None if data is None else json.loads(data)


class Cache:
    """Content-addressed download cache shared by every edition and run.

    Files are stored by their verified digest, so a cached file is never reused unless
    it hashed correctly when it was first downloaded."""

    def __init__(self, root: Path):
        self.root = Path(root)
        (self.root / 'blobs').mkdir(parents=True, exist_ok=True)
        (self.root / 'meta').mkdir(parents=True, exist_ok=True)
        (self.root / 'tmp').mkdir(parents=True, exist_ok=True)
        self._locks = {}
        self._guard = threading.Lock()

    def _lock(self, key):
        with self._guard:
            return self._locks.setdefault(key, threading.Lock())

    def blob(self, algo, digest):
        return self.root / 'blobs' / algo / digest[:2] / digest

    def meta_path(self, key):
        safe = hashlib.sha256(key.encode()).hexdigest()
        return self.root / 'meta' / safe

    def cached_get(self, url, *, max_age=None, allow_404=False, timeout=120):
        """Fetch a metadata document, cached on disk by URL (not a release input)."""
        path = self.meta_path(url)
        with self._lock('meta:' + url):
            return self._cached_get(url, path, max_age, allow_404, timeout)

    def _cached_get(self, url, path, max_age, allow_404, timeout=120):
        if path.exists() and (max_age is None or time.time() - path.stat().st_mtime < max_age):
            data = path.read_bytes()
            return None if data == b'\0__404__' else data
        data = http_get(url, allow_404=allow_404, timeout=timeout, retries=3 if timeout < 60 else 4)
        tmp = path.with_name(path.name + '.' + uuid.uuid4().hex)
        tmp.write_bytes(b'\0__404__' if data is None else data)
        os.replace(tmp, path)
        return data

    def cached_json(self, url, **kw):
        data = self.cached_get(url, **kw)
        return None if data is None else json.loads(data)

    def fetch(self, urls, algo, digest, *, size=None):
        """Download the first working URL into the cache and verify algo:digest.

        Returns (path, url). Raises VerificationError if every candidate that answered
        delivered bytes with a different digest, or Unresolved if none answered."""
        if isinstance(urls, str):
            urls = [urls]
        digest = digest.lower()
        with self._lock(f'{algo}:{digest}'):
            return self._fetch(urls, algo, digest, size)

    def _fetch(self, urls, algo, digest, size):
        target = self.blob(algo, digest)
        if target.exists():
            return target, urls[0]
        errors = []
        for url in urls:
            tmp = self.root / 'tmp' / f'{os.getpid()}-{uuid.uuid4().hex}'
            try:
                h = hashlib.new(algo)
                with _open(url, 600) as resp, open(tmp, 'wb') as out:
                    for block in iter(lambda: resp.read(1 << 20), b''):
                        h.update(block)
                        out.write(block)
            except Exception as exc:  # network errors: try the next mirror
                errors.append(f'{url}: {exc}')
                tmp.unlink(missing_ok=True)
                continue
            got = h.hexdigest()
            if got != digest:
                tmp.unlink(missing_ok=True)
                raise VerificationError(f'{url}: {algo} {got} != expected {digest}')
            got_size = tmp.stat().st_size
            if size is not None and got_size != int(size):
                tmp.unlink(missing_ok=True)
                raise VerificationError(f'{url}: size {got_size} != expected {size}')
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp, target)
            return target, url
        raise Unresolved('download failed: ' + '; '.join(errors)[-1500:])

    def fetch_unverified(self, url):
        """Download a file whose expected hash is not known in advance (the caller must
        verify it by other means, e.g. a git object id). Stored by its own SHA-256."""
        data = http_get(url)
        digest = sha256_bytes(data)
        target = self.blob('sha256', digest)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return target, digest

    def adopt(self, path, algo='sha256'):
        """Move a locally produced, already verified file into the cache."""
        digest = sha256_file(path, algo)
        target = self.blob(algo, digest)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), target)
        else:
            Path(path).unlink()
        return target, digest


def place(src: Path, dest: Path):
    """Hard-link (or copy) a cached blob into the output tree."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    try:
        os.link(src, dest)
    except OSError:
        shutil.copyfile(src, dest)


# ---------------------------------------------------------------- licences
# Category order: strong > weak > permissive. A component is copyleft when any licence
# that applies to it (conjunctively, or as the only choice) is strong or weak copyleft.

_STRONG = [
    (r'\bA-?GPL|\bAFFERO\b|GNU AFFERO', 'AGPL'),
    (r'(?<![L])\bGPL|GNU GENERAL PUBLIC|\bGPLv?\d|GNU GPL', 'GPL'),
    (r'\bSleepycat\b', 'Sleepycat'),
    (r'\bOSL-?\d|Open Software License', 'OSL'),
    (r'\bEUPL\b|European Union Public', 'EUPL'),
    (r'\bQPL\b', 'QPL'),
    (r'\bSSPL\b', 'SSPL'),
    (r'\bCC-BY-SA\b|ShareAlike', 'CC-BY-SA'),
]
_WEAK = [
    (r'\bLGPL|GNU LESSER|GNU LIBRARY GENERAL|\bLesser General Public', 'LGPL'),
    (r'\bMPL\b|MPL-?\d|Mozilla Public License|\bMPLv?\d', 'MPL'),
    (r'\bEPL\b|EPL-?\d|Eclipse Public License|\bEPLv?\d', 'EPL'),
    (r'\bCDDL\b|Common Development and Distribution', 'CDDL'),
    (r'\bCPL-?1|Common Public License', 'CPL'),
    (r'\bIPL-?1|IBM Public License', 'IPL'),
    (r'\bErlPL\b|Erlang Public', 'ErlPL'),
    (r'\bLPPL\b|LaTeX Project Public', 'LPPL'),
    (r'\bAPSL\b|Apple Public Source', 'APSL'),
    (r'\bMS-RL\b|Microsoft Reciprocal', 'MS-RL'),
    (r'\bOFL\b|Open Font License', 'OFL'),
]
_NOT_COPYLEFT = [
    # Names that contain a copyleft keyword but are permissive.
    r'Eclipse Distribution License', r'\bEDL\b', r'GPL[- ]?compatible',
]


def licence_family(text):
    """Return (category, family) for one licence name/expression term."""
    t = text or ''
    for pat in _NOT_COPYLEFT:
        t = re.sub(pat, ' ', t, flags=re.I)
    for pat, fam in _WEAK:  # LGPL before GPL so "LGPL" is not read as GPL
        if re.search(pat, t, flags=re.I):
            return 'weak', fam
    for pat, fam in _STRONG:
        if re.search(pat, t, flags=re.I):
            return 'strong', fam
    if not t.strip():
        return 'unknown', ''
    return 'permissive', t.strip()


def _split_top(expr, sep):
    """Split an SPDX/RPM/APK licence expression at top-level occurrences of sep."""
    parts, depth, cur, i = [], 0, '', 0
    pat = re.compile(r'\s+' + sep + r'\s+', re.I)
    while i < len(expr):
        ch = expr[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if depth == 0:
            m = pat.match(expr, i)
            if m:
                parts.append(cur)
                cur = ''
                i = m.end()
                continue
        cur += ch
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def _strip_parens(expr):
    expr = expr.strip()
    while expr.startswith('(') and expr.endswith(')'):
        depth = 0
        for i, ch in enumerate(expr):
            depth += ch == '('
            depth -= ch == ')'
            if depth == 0 and i != len(expr) - 1:
                return expr
        expr = expr[1:-1].strip()
    return expr


def classify_expression(expr):
    """Classify a licence expression (SPDX, RPM 'and/or' or APK space-separated).

    Returns dict(category, families, elected) where category is one of
    'copyleft', 'elected-permissive', 'permissive', 'unknown'."""
    expr = _strip_parens((expr or '').strip())
    if not expr:
        return {'category': 'unknown', 'families': [], 'elected': None}
    ors = _split_top(expr, 'or')
    if len(ors) > 1:
        results = [classify_expression(p) for p in ors]
        for r, p in zip(results, ors):
            if r['category'] in ('permissive', 'elected-permissive'):
                fams = sorted({f for x in results for f in x['families']})
                if any(x['category'] == 'copyleft' for x in results):
                    return {'category': 'elected-permissive', 'families': fams, 'elected': p}
                return {'category': r['category'], 'families': fams, 'elected': r.get('elected')}
        fams = sorted({f for x in results for f in x['families']})
        cat = 'copyleft' if any(x['category'] == 'copyleft' for x in results) else 'unknown'
        return {'category': cat, 'families': fams, 'elected': None}
    ands = _split_top(expr, 'and')
    if len(ands) > 1:
        results = [classify_expression(p) for p in ands]
        fams = sorted({f for x in results for f in x['families']})
        if any(x['category'] == 'copyleft' for x in results):
            return {'category': 'copyleft', 'families': fams, 'elected': None}
        if any(x['category'] == 'unknown' for x in results):
            return {'category': 'unknown', 'families': fams, 'elected': None}
        return {'category': 'permissive', 'families': fams, 'elected': None}
    # APK uses whitespace-separated lists that mean AND (e.g. "GPL-2.0-only MIT").
    if ' ' in expr and not re.search(r'\b(with|exception|version|license|public|v\d)\b', expr, re.I) \
            and all(re.fullmatch(r'[A-Za-z0-9.+\-]+', w) for w in expr.split()):
        return classify_expression(' AND '.join(expr.split()))
    cat, fam = licence_family(expr)
    if cat in ('strong', 'weak'):
        return {'category': 'copyleft', 'families': [fam], 'elected': None}
    return {'category': cat, 'families': [fam] if fam and cat != 'permissive' else [], 'elected': None}


def all_families(text):
    """Every copyleft family named anywhere in a free-form text."""
    t = text or ''
    for pat in _NOT_COPYLEFT:
        t = re.sub(pat, ' ', t, flags=re.I)
    found = set()
    for pat, fam in _WEAK:
        if re.search(pat, t, flags=re.I):
            found.add(fam)
    t2 = re.sub(r'\bLGPL|GNU LESSER|GNU LIBRARY GENERAL', ' ', t, flags=re.I)
    for pat, fam in _STRONG:
        if re.search(pat, t2, flags=re.I):
            found.add(fam)
    return found


def classify_texts(texts):
    """Conservative classification of free-form licence texts (copyright files, LICENSE
    files, POM licence names): copyleft if any text names a copyleft licence."""
    fams = set()
    for t in texts:
        fams |= all_families(t)
    if fams:
        return {'category': 'copyleft', 'families': sorted(fams), 'elected': None}
    if any((t or '').strip() for t in texts):
        return {'category': 'permissive', 'families': [], 'elected': None}
    return {'category': 'unknown', 'families': [], 'elected': None}


# ---------------------------------------------------------------- records

@dataclasses.dataclass
class SourceFile:
    path: str            # relative to the edition output directory
    sha256: str
    size: int
    origin: str          # URL (or git URL@commit:path) it came from
    verification: str    # how its integrity was established

    def asdict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Component:
    key: str                      # unique id, e.g. debian:glibc@2.41-12+deb13u4
    ecosystem: str                # debian | alpine | rpm | maven | go | jdk | busybox | git | pypi | npm
    name: str
    version: str
    licence: str
    category: str                 # copyleft | elected-permissive | permissive | unknown
    families: list
    images: dict = dataclasses.field(default_factory=dict)   # image ref -> sorted arches
    evidence: list = dataclasses.field(default_factory=list)  # where it was found
    files: list = dataclasses.field(default_factory=list)
    status: str = 'pending'       # resolved | unresolved | not-required
    reason: str = ''
    notes: list = dataclasses.field(default_factory=list)
    fetch: dict = dataclasses.field(default_factory=dict)     # handler-private plan

    def needs_source(self):
        return self.category in ('copyleft', 'unknown')

    def add_image(self, ref, arch, where=None):
        arches = set(self.images.get(ref, []))
        arches.add(arch)
        self.images[ref] = sorted(arches)
        if where and where not in self.evidence:
            self.evidence.append(where)

    def asdict(self):
        d = dataclasses.asdict(self)
        d.pop('fetch')
        d['files'] = [f.asdict() if isinstance(f, SourceFile) else f for f in self.files]
        d['evidence'] = sorted(self.evidence)[:20] + ([f'... {len(self.evidence) - 20} more']
                                                      if len(self.evidence) > 20 else [])
        return d


def slug(text):
    return re.sub(r'[^A-Za-z0-9._+-]+', '_', text).strip('_')[:150]


def quote_url(part):
    return urllib.parse.quote(part, safe='')
