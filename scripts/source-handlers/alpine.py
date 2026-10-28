"""Alpine packages: /lib/apk/db/installed -> aports at the exact build commit.

Each installed package records the aports commit it was built from (`c:`) and its
origin directory (`o:`). The package directory is downloaded from that commit and every
file is checked against the git blob id reported for that commit's tree (from Alpine
GitLab or, when GitLab is unreachable, the official alpinelinux/aports mirror). The
APKBUILD's `source=` is evaluated (inside a network-less throwaway container of the image
itself) and each distfile is downloaded and checked against the APKBUILD `sha512sums`."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from common import (Component, Unresolved, VerificationError, aggregate_expressions,
                    http_get, log, quote_url, slug)

GITLAB = 'https://gitlab.alpinelinux.org'
PROJECT = 'alpine%2Faports'
GITHUB_API = 'https://api.github.com/repos/alpinelinux/aports'
GITHUB_RAW = 'https://raw.githubusercontent.com/alpinelinux/aports'
GITHUB_GIT = 'https://github.com/alpinelinux/aports.git'
GITHUB_WEB = 'https://github.com/alpinelinux/aports'
DISTFILES = 'https://distfiles.alpinelinux.org/distfiles'

APORTS_HTTP_TIMEOUT = 20
APORTS_HTTP_RETRIES = 2
APORTS_GIT_TIMEOUT = 120
APORTS_PREPARE_DEADLINE = 600
APORTS_PROVIDER_MAX_FAILURES = 1


def parse_installed(text):
    rows = []
    for block in (text or '').strip().split('\n\n'):
        row = {}
        for line in block.splitlines():
            if len(line) > 1 and line[1] == ':':
                row.setdefault(line[0], line[2:])
        if row.get('P'):
            rows.append(row)
    return rows


def release_branch(facts):
    for text in (facts.get('os_release') or {}).values():
        m = re.search(r'^VERSION_ID="?(\d+)\.(\d+)', text, re.M)
        if m and re.search(r'^ID="?alpine', text, re.M):
            return f'v{m.group(1)}.{m.group(2)}'
    return None


def is_azul(row):
    return 'azul' in (row.get('m') or '').lower()


def components(facts, image_ref, arch, _cache, registry):
    rows = parse_installed(facts.get('apk_installed'))
    if not rows:
        return 0
    branch = release_branch(facts)
    groups = {}
    for r in rows:
        if r['P'].startswith('.') and not r.get('c'):
            continue  # virtual dependency bundle (e.g. .postgresql-rundeps), no code
        if is_azul(r):
            continue  # Azul Zulu JDK packages are handled by the JDK handler
        groups.setdefault((r.get('o') or r['P'], r['V'], r.get('c') or ''), []).append(r)
    for (origin, ver, commit), pkgs in sorted(groups.items()):
        key = f'alpine:{origin}@{ver}' + ('' if commit else ':no-aports-commit')
        comp = registry.get(key)
        if comp is None:
            licences = sorted({p.get('L', '') for p in pkgs})
            cat, fams = aggregate_expressions(licences)
            comp = Component(key=key, ecosystem='alpine', name=origin, version=ver,
                             licence=' AND '.join(l for l in licences if l) or '(none declared)',
                             category=cat, families=fams)
            comp.fetch = {'commit': commit, 'branch': branch, 'arches': set(), 'apk_arch': set()}
            if not commit:
                comp.notes.append('package has no aports commit (not built from Alpine aports); '
                                  f'maintainer: {pkgs[0].get("m", "")}')
            registry[key] = comp
        comp.fetch['apk_arch'].add(pkgs[0].get('A') or arch)
        if branch and comp.fetch.get('branch') != branch:
            comp.fetch.setdefault('other_branches', set()).add(branch)
        for p in pkgs:
            comp.add_image(image_ref, arch, f'{p["P"]} {p["V"]} ({p.get("A")}) L:{p.get("L")}')
        comp.fetch['eval_image'] = (image_ref, facts.get('resolved_ref'), arch)
    return len(groups)


def git_blob_sha1(data):
    return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()


def _gh_headers():
    tok = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    return {'Authorization': f'Bearer {tok}'} if tok else {}


class _AportsSession:
    """Bounds an Alpine aports retrieval run and circuit-breaks failing providers."""

    def __init__(self, deadline=None):
        self.deadline = deadline
        self.failures: dict[str, int] = {}
        self.tripped: dict[str, str] = {}
        self.fetched_commits: set[str] = set()
        self.tree_cache: dict[tuple[str, str], tuple[str, list[dict]]] = {}
        self.pending_comps: list = []
        self.batch_primed = False

    def check_deadline(self, context):
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise Unresolved(f'Alpine aports preparation deadline exceeded ({context})')

    def effective_timeout(self, base_timeout):
        if self.deadline is None:
            return base_timeout
        rem = self.deadline - time.monotonic()
        if rem <= 0:
            raise Unresolved('Alpine aports preparation deadline exceeded')
        return max(0.1, min(float(base_timeout), rem))

    def is_tripped(self, provider):
        return provider in self.tripped

    def record_failure(self, provider, context, exc):
        count = self.failures.get(provider, 0) + 1
        self.failures[provider] = count
        detail = f'{context}: {type(exc).__name__}: {exc}'
        if count >= APORTS_PROVIDER_MAX_FAILURES and provider not in self.tripped:
            self.tripped[provider] = detail
            log(f'alpine aports provider {provider} failed ({detail}); marking provider unavailable')
        else:
            log(f'alpine aports provider {provider} error ({detail})')


def _session_for(cache, deadline=None):
    sess = getattr(cache, '_alpine_session', None) if cache is not None else None
    if sess is None:
        sess = _AportsSession(deadline=deadline)
        if cache is not None:
            cache._alpine_session = sess
    elif deadline is not None:
        sess.deadline = deadline
    return sess


def _aports_bare_repo(cache):
    path = Path(cache.root) / 'git' / (slug(GITHUB_GIT.split('://', 1)[-1]) + '.git')
    if not (path / 'HEAD').exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(['git', 'init', '-q', '--bare', str(path)],
                             capture_output=True, text=True, timeout=30)
        if res.returncode:
            raise RuntimeError(f'git init failed ({res.returncode}): {(res.stderr or "").strip()}')
        res = subprocess.run(['git', '-C', str(path), 'remote', 'add', 'origin', GITHUB_GIT],
                             capture_output=True, text=True, timeout=30)
        if res.returncode:
            raise RuntimeError(f'git remote add failed ({res.returncode}): {(res.stderr or "").strip()}')
    else:
        subprocess.run(['git', '-C', str(path), 'remote', 'set-url', 'origin', GITHUB_GIT],
                       capture_output=True, text=True, timeout=30)
    return path


def _has_git_object(bare: Path, spec: str) -> bool:
    proc = subprocess.run(['git', '-C', str(bare), 'cat-file', '-e', spec],
                          capture_output=True, text=True, timeout=30)
    return proc.returncode == 0


def _ensure_git_commits(cache, commits, session: _AportsSession):
    bare = _aports_bare_repo(cache)
    missing = [c for c in sorted(set(commits))
               if c and c not in session.fetched_commits and not _has_git_object(bare, f'{c}^{{commit}}')]
    for c in commits:
        if c and c not in missing:
            session.fetched_commits.add(c)
    if not missing:
        return bare
    session.check_deadline(f'git fetch {len(missing)} aports commit(s)')
    log(f'alpine aports provider github-git: fetching {len(missing)} commit tree(s) from {GITHUB_GIT}')
    proc = subprocess.run(
        ['git', '-C', str(bare), 'fetch', '-q', '--depth', '1', '--filter=blob:none', 'origin', *missing],
        capture_output=True, text=True, timeout=session.effective_timeout(APORTS_GIT_TIMEOUT),
    )
    if proc.returncode == 0:
        session.fetched_commits.update(missing)
        return bare
    if len(missing) == 1:
        err = (proc.stderr or '').strip()[-240:] or f'exit {proc.returncode}'
        raise RuntimeError(f'git fetch {missing[0][:12]} from {GITHUB_GIT} failed: {err}')
    # If one commit in a batch is invalid on the remote, fetch valid commits individually.
    ok_any = False
    last_err = (proc.stderr or '').strip()[-240:] or f'exit {proc.returncode}'
    for c in missing:
        session.check_deadline(f'git fetch commit {c[:12]}')
        single = subprocess.run(
            ['git', '-C', str(bare), 'fetch', '-q', '--depth', '1', '--filter=blob:none', 'origin', c],
            capture_output=True, text=True, timeout=session.effective_timeout(APORTS_GIT_TIMEOUT),
        )
        if single.returncode == 0 and _has_git_object(bare, f'{c}^{{commit}}'):
            session.fetched_commits.add(c)
            ok_any = True
        else:
            last_err = (single.stderr or '').strip()[-240:] or f'exit {single.returncode}'
    if not ok_any:
        raise RuntimeError(f'git fetch from {GITHUB_GIT} failed: {last_err}')
    return bare


def _git_ls_origin_tree(bare: Path, origin: str, commit: str, session: _AportsSession):
    session.check_deadline(f'git ls-tree {origin}@{commit[:12]}')
    paths = [f'{r}/{origin}' for r in ('main', 'community', 'testing')]
    proc = subprocess.run(
        ['git', '-C', str(bare), 'ls-tree', '-r', '-z', '--full-tree', commit, '--', *paths],
        capture_output=True, timeout=session.effective_timeout(30),
    )
    if proc.returncode:
        err = (proc.stderr or b'').decode('utf-8', 'replace').strip()[-240:]
        raise RuntimeError(f'git ls-tree {commit[:12]} failed ({proc.returncode}): {err}')
    by_repo: dict[str, list[dict]] = {'main': [], 'community': [], 'testing': []}
    for rec in proc.stdout.split(b'\0'):
        if not rec or b'\t' not in rec:
            continue
        meta, raw_path = rec.split(b'\t', 1)
        parts = meta.decode('ascii', 'replace').split()
        if len(parts) != 3:
            continue
        _mode, typ, oid = parts
        if typ != 'blob':
            continue
        path_str = raw_path.decode('utf-8', 'surrogateescape')
        repo = path_str.split('/', 1)[0]
        if repo in by_repo and path_str.startswith(f'{repo}/{origin}/'):
            by_repo[repo].append({'id': oid, 'path': path_str, 'type': 'blob', 'provider': 'github-git'})
    for repo in ('main', 'community', 'testing'):
        if by_repo[repo]:
            return repo, by_repo[repo]
    return None, []


def _git_fetch_blobs(cache, oids, session: _AportsSession):
    missing = sorted({oid for oid in oids if oid and not cache.blob('gitblob', oid).exists()})
    if not missing:
        return
    bare = _aports_bare_repo(cache)
    to_download = [oid for oid in missing if not _has_git_object(bare, f'{oid}^{{blob}}')]
    if to_download:
        session.check_deadline(f'git fetch {len(to_download)} blob(s)')
        log(f'alpine aports provider github-git: fetching {len(to_download)} blob(s) from {GITHUB_GIT}')
        proc = subprocess.run(
            ['git', '-C', str(bare), 'fetch', '-q', '--no-write-fetch-head', 'origin', *to_download],
            capture_output=True, text=True, timeout=session.effective_timeout(APORTS_GIT_TIMEOUT),
        )
        if proc.returncode:
            err = (proc.stderr or '').strip()[-240:] or f'exit {proc.returncode}'
            raise RuntimeError(f'git blob fetch from {GITHUB_GIT} failed: {err}')
    session.check_deadline(f'git cat-file {len(missing)} blob(s)')
    proc = subprocess.run(
        ['git', '-C', str(bare), 'cat-file', '--batch'],
        input=('\n'.join(missing) + '\n').encode('ascii'),
        capture_output=True, timeout=session.effective_timeout(60),
    )
    if proc.returncode:
        err = (proc.stderr or b'').decode('utf-8', 'replace').strip()[-240:]
        raise RuntimeError(f'git cat-file --batch failed ({proc.returncode}): {err}')
    buf = proc.stdout
    pos = 0
    for oid in missing:
        nl = buf.find(b'\n', pos)
        if nl < 0:
            raise RuntimeError(f'truncated git cat-file output at {oid}')
        header = buf[pos:nl].decode('ascii', 'replace').split()
        pos = nl + 1
        if len(header) < 3 or header[1] != 'blob':
            raise RuntimeError(f'git object {oid} missing from cat-file ({header})')
        size = int(header[2])
        data = buf[pos:pos + size]
        pos += size + 1  # trailing newline after blob payload
        got = git_blob_sha1(data)
        if got != oid:
            raise VerificationError(f'git blob {got} != expected {oid}')
        target = cache.blob('gitblob', oid)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + '.' + uuid.uuid4().hex)
        tmp.write_bytes(data)
        os.replace(tmp, target)


def _batch_prime_git_aports(cache, comps, session: _AportsSession):
    if session.batch_primed or session.is_tripped('github-git'):
        return
    session.batch_primed = True
    commits = sorted({c.fetch.get('commit') for c in comps if c.fetch.get('commit')})
    if not commits:
        return
    bare = _ensure_git_commits(cache, commits, session)
    all_oids = []
    for comp in comps:
        commit = comp.fetch.get('commit')
        if not commit or (comp.name, commit) in session.tree_cache:
            continue
        if commit not in session.fetched_commits and not _has_git_object(bare, f'{commit}^{{commit}}'):
            continue
        repo, entries = _git_ls_origin_tree(bare, comp.name, commit, session)
        if repo and entries:
            session.tree_cache[(comp.name, commit)] = (repo, entries)
            all_oids.extend(e['id'] for e in entries)
    if all_oids:
        _git_fetch_blobs(cache, all_oids, session)


def _gitlab_tree(cache, origin, commit, session: _AportsSession):
    for repo in ('main', 'community', 'testing'):
        data, page = [], 1
        while True:
            session.check_deadline(f'gitlab tree {repo}/{origin}@{commit[:12]}')
            url = (f'{GITLAB}/api/v4/projects/{PROJECT}/repository/tree?path={repo}/{quote_url(origin)}'
                   f'&ref={commit}&recursive=true&per_page=100&page={page}')
            chunk = cache.cached_json(url, allow_404=True,
                                      timeout=session.effective_timeout(APORTS_HTTP_TIMEOUT),
                                      retries=APORTS_HTTP_RETRIES, deadline=session.deadline)
            data += chunk or []
            if not chunk or len(chunk) < 100:
                break
            page += 1
        if data:
            return repo, [{**e, 'provider': 'gitlab'} for e in data if e['type'] == 'blob']
    return None, []


def _github_git_tree(cache, origin, commit, session: _AportsSession):
    if session.pending_comps and not session.batch_primed:
        _batch_prime_git_aports(cache, session.pending_comps, session)
    cached = session.tree_cache.get((origin, commit))
    if cached is not None:
        return cached
    bare = _ensure_git_commits(cache, [commit], session)
    if not _has_git_object(bare, f'{commit}^{{commit}}'):
        raise Unresolved(f'aports commit {commit} not found in {GITHUB_GIT}')
    repo, entries = _git_ls_origin_tree(bare, origin, commit, session)
    if repo and entries:
        session.tree_cache[(origin, commit)] = (repo, entries)
    return repo, entries


def _github_http_list_dir(cache, rel_path, commit, session: _AportsSession):
    session.check_deadline(f'github contents {rel_path}@{commit[:12]}')
    url = f'{GITHUB_API}/contents/{rel_path}?ref={commit}'
    items = cache.cached_json(url, allow_404=True, headers=_gh_headers(),
                              timeout=session.effective_timeout(APORTS_HTTP_TIMEOUT),
                              retries=APORTS_HTTP_RETRIES, deadline=session.deadline)
    if not items:
        return []
    if isinstance(items, dict):
        items = [items]
    blobs = []
    for it in items:
        if it.get('type') == 'dir':
            blobs.extend(_github_http_list_dir(cache, it['path'], commit, session))
        elif it.get('type') in ('file', 'symlink') and it.get('sha') and it.get('path'):
            blobs.append({'id': it['sha'], 'path': it['path'], 'type': 'blob', 'provider': 'github-http'})
    return blobs


def _github_http_tree(cache, origin, commit, session: _AportsSession):
    for repo in ('main', 'community', 'testing'):
        blobs = _github_http_list_dir(cache, f'{repo}/{quote_url(origin)}', commit, session)
        if blobs:
            return repo, blobs
    return None, []


def aports_tree(cache, origin, commit, *, session=None):
    """Return (repo, entries) for main|community|testing/<origin> at commit."""
    sess = session or _session_for(cache)
    sess.check_deadline(f'{origin}@{commit[:12]}')
    providers = (
        ('gitlab', _gitlab_tree),
        ('github-git', _github_git_tree),
        ('github-http', _github_http_tree),
    )
    attempted = False
    for name, fn in providers:
        if sess.is_tripped(name):
            continue
        attempted = True
        try:
            repo, entries = fn(cache, origin, commit, sess)
        except (Unresolved, VerificationError):
            raise
        except Exception as exc:
            sess.record_failure(name, f'{origin}@{commit[:12]}', exc)
            continue
        if entries:
            return repo, entries
        raise Unresolved(f'aports commit {commit} has no main|community|testing/{origin}')
    reasons = '; '.join(f'{k}: {v}' for k, v in sess.tripped.items()) or 'no providers available'
    if not attempted:
        raise Unresolved(f'aports providers circuit-broken before {origin}@{commit[:12]} ({reasons})')
    raise Unresolved(f'aports tree lookup failed for {origin}@{commit[:12]} ({reasons})')


def fetch_aports_dir(cache, origin, commit, *, session=None):
    sess = session or _session_for(cache)
    sess.check_deadline(f'{origin}@{commit[:12]}')
    repo, entries = aports_tree(cache, origin, commit, session=sess)
    missing = [e for e in entries if not cache.blob('gitblob', e['id']).exists()]
    if missing and not sess.is_tripped('gitlab') and all(e.get('provider') == 'gitlab' for e in entries):
        for e in list(missing):
            sess.check_deadline(f'gitlab blob {e["id"][:12]}')
            url = f'{GITLAB}/api/v4/projects/{PROJECT}/repository/blobs/{e["id"]}/raw'
            try:
                data = http_get(url, timeout=sess.effective_timeout(APORTS_HTTP_TIMEOUT),
                                retries=APORTS_HTTP_RETRIES, deadline=sess.deadline)
            except Exception as exc:
                sess.record_failure('gitlab', f'blob {e["id"][:12]} ({origin}@{commit[:12]})', exc)
                break
            got = git_blob_sha1(data)
            if got != e['id']:
                raise VerificationError(f'{e["path"]}: git blob {got} != tree entry {e["id"]}')
            path = cache.blob('gitblob', e['id'])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    missing = [e for e in entries if not cache.blob('gitblob', e['id']).exists()]
    if missing and not sess.is_tripped('github-git'):
        try:
            _git_fetch_blobs(cache, [e['id'] for e in missing], sess)
        except (Unresolved, VerificationError):
            raise
        except Exception as exc:
            sess.record_failure('github-git', f'blobs for {origin}@{commit[:12]}', exc)
    missing = [e for e in entries if not cache.blob('gitblob', e['id']).exists()]
    if missing and not sess.is_tripped('github-http'):
        for e in list(missing):
            sess.check_deadline(f'github raw {e["path"]}@{commit[:12]}')
            raw_url = f'{GITHUB_RAW}/{commit}/{e["path"]}'
            try:
                data = http_get(raw_url, timeout=sess.effective_timeout(APORTS_HTTP_TIMEOUT),
                                retries=APORTS_HTTP_RETRIES, deadline=sess.deadline)
            except Exception as exc:
                sess.record_failure('github-http', f'{e["path"]}@{commit[:12]}', exc)
                break
            got = git_blob_sha1(data)
            if got != e['id']:
                raise VerificationError(f'{e["path"]}: git blob {got} != tree entry {e["id"]}')
            path = cache.blob('gitblob', e['id'])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    files = []
    for e in entries:
        path = cache.blob('gitblob', e['id'])
        if not path.exists():
            reasons = '; '.join(f'{k}: {v}' for k, v in sess.tripped.items()) or 'all blob providers failed'
            raise Unresolved(f'aports blob {e["id"][:12]} ({e["path"]}) unavailable: {reasons}')
        if e.get('provider') == 'gitlab' and not sess.is_tripped('gitlab'):
            url = f'{GITLAB}/api/v4/projects/{PROJECT}/repository/blobs/{e["id"]}/raw'
        else:
            url = f'{GITHUB_WEB}/blob/{commit}/{e["path"]}'
        files.append((path, e['path'], url, e['id']))
    return repo, files


EVAL_SCRIPT = r'''
for d in /w/*/; do
  (
    cd "$d" || exit 0
    CARCH="$(cat .carch)"; CBUILD="$CARCH-alpine-linux-musl"; CHOST="$CBUILD"; CTARGET="$CBUILD"
    CTARGET_ARCH="$CARCH"; CLIBC=musl; srcdir=/tmp/src; startdir="$d"; builddir=/tmp/build
    export CARCH CBUILD CHOST CTARGET CTARGET_ARCH CLIBC srcdir startdir builddir
    . ./APKBUILD >/dev/null 2>&1
    printf '@@ %s\n' "$(basename "$d")"
    printf 'V %s-r%s\n' "$pkgver" "$pkgrel"
    for s in $source; do printf 'S %s\n' "$s"; done
    printf '%s\n' "$sha512sums" | while read -r h f; do [ -n "$h" ] && printf 'H %s %s\n' "$h" "$f"; done
  )
done
exit 0
'''


def evaluate_apkbuilds(jobs, workroot: Path):
    """jobs: list of (job_id, apkbuild_path, carch, image_ref, platform_arch).

    Runs one container per (image, arch) with --network none and the APKBUILDs mounted
    read-only. Returns {job_id: {'version', 'sources', 'sha512'}}."""
    results = {}
    by_image = {}
    for job in jobs:
        by_image.setdefault((job[3], job[4]), []).append(job)
    for (image, arch), items in by_image.items():
        work = Path(workroot).resolve() / f'apkeval-{uuid.uuid4().hex[:10]}'
        work.mkdir(parents=True)
        try:
            for job_id, apkbuild, carch, _i, _a in items:
                d = work / job_id
                d.mkdir()
                shutil.copyfile(apkbuild, d / 'APKBUILD')
                (d / '.carch').write_text(carch)
            name = f'krate-collect-sources-apkeval-{uuid.uuid4().hex[:10]}'
            proc = subprocess.run(['docker', 'run', '--rm', '--name', name, '--network', 'none',
                                   '--platform', f'linux/{arch}', '--user', '65534:65534',
                                   '--entrypoint', '/bin/sh', '-v', f'{work}:/w:ro', image, '-c', EVAL_SCRIPT],
                                  capture_output=True, text=True, timeout=600)
            if proc.returncode or not proc.stdout.strip():
                log(f'APKBUILD evaluation in {image} exited {proc.returncode}: {proc.stderr[-300:]}')
            cur = None
            for line in proc.stdout.splitlines():
                if line.startswith('@@ '):
                    cur = results.setdefault(line[3:].strip(), {'version': None, 'sources': [], 'sha512': {}})
                elif cur is None:
                    continue
                elif line.startswith('V '):
                    cur['version'] = line[2:].strip()
                elif line.startswith('S '):
                    cur['sources'].append(line[2:].strip())
                elif line.startswith('H '):
                    _, h, f = line.split(' ', 2)
                    cur['sha512'][f.strip()] = h.strip()
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return results


def source_name(entry):
    if '::' in entry:
        return entry.split('::', 1)[0], entry.split('::', 1)[1]
    if '://' in entry:
        return entry.rstrip('/').rsplit('/', 1)[-1], entry
    return entry, None


def prepare(comps, cache, workroot, *, deadline=None):
    """Download aports directories and evaluate their APKBUILDs (batched)."""
    todo = [c for c in comps if c.fetch.get('commit')]
    if not todo:
        return
    eff_deadline = deadline if deadline is not None else (time.monotonic() + APORTS_PREPARE_DEADLINE)
    sess = _AportsSession(deadline=eff_deadline)
    sess.pending_comps = todo
    if cache is not None:
        cache._alpine_session = sess
    commits = sorted({c.fetch['commit'] for c in todo})
    log(f'preparing {len(todo)} Alpine packages across {len(commits)} aports commits')
    jobs = []
    ok_count = 0
    fail_count = 0
    for idx, comp in enumerate(todo, 1):
        commit = comp.fetch['commit']
        try:
            repo, files = fetch_aports_dir(cache, comp.name, commit, session=sess)
        except (Unresolved, VerificationError) as exc:
            comp.fetch['error'] = exc
            fail_count += 1
            log(f'alpine aports [{idx}/{len(todo)}] {comp.name}@{commit[:12]}: unresolved ({exc})')
            continue
        except Exception as exc:  # network/API failure: report it on the component
            comp.fetch['error'] = Unresolved(f'aports download failed: {type(exc).__name__}: {exc}')
            fail_count += 1
            log(f'alpine aports [{idx}/{len(todo)}] {comp.name}@{commit[:12]}: unresolved ({comp.fetch["error"]})')
            continue
        comp.fetch['repo'] = repo
        comp.fetch['aports_files'] = files
        apkbuild = next((f[0] for f in files if f[1].endswith(f'/{comp.name}/APKBUILD')), None)
        if not apkbuild:
            comp.fetch['error'] = Unresolved(f'no APKBUILD in {repo}/{comp.name}@{commit}')
            fail_count += 1
            log(f'alpine aports [{idx}/{len(todo)}] {comp.name}@{commit[:12]}: unresolved ({comp.fetch["error"]})')
            continue
        ok_count += 1
        if idx == 1 or idx == len(todo) or idx % 10 == 0:
            provider = 'alpinelinux/aports mirror' if 'github' in files[0][2] else 'gitlab'
            log(f'alpine aports [{idx}/{len(todo)}] {comp.name}@{commit[:12]}: {len(files)} file(s) via {provider} ({repo})')
        image_ref, resolved, arch = comp.fetch['eval_image']
        for carch in sorted(comp.fetch['apk_arch']):
            job_id = f'{slug(comp.name)}--{carch}--{uuid.uuid4().hex[:6]}'
            comp.fetch.setdefault('jobs', []).append((job_id, carch))
            jobs.append((job_id, apkbuild, carch, resolved, arch))
    log(f'prepared {ok_count}/{len(todo)} Alpine aports directories ({fail_count} unresolved)')
    if jobs:
        log(f'evaluating {len(jobs)} APKBUILDs in network-less containers')
        results = evaluate_apkbuilds(jobs, workroot)
        for comp in comps:
            for job_id, carch in comp.fetch.get('jobs', []):
                comp.fetch.setdefault('eval', {})[carch] = results.get(job_id)
        log(f'evaluated {len(results)}/{len(jobs)} APKBUILDs')


def fetch(comp, cache, _out_dir, rel_root):
    if comp.fetch.get('error'):
        raise comp.fetch['error']
    commit = comp.fetch.get('commit')
    if not commit:
        raise Unresolved('package was not built from Alpine aports (no commit in the apk database); '
                         'its packager does not publish the build recipe in aports')
    base = f'{rel_root}/alpine/{slug(comp.name)}/{slug(comp.version)}'
    files = []
    for path, gpath, url, blob in comp.fetch['aports_files']:
        rel_in_dir = gpath.split(f'/{comp.name}/', 1)[1]
        provider_note = 'alpinelinux/aports mirror' if 'github' in url else 'GitLab tree'
        files.append((path, f'{base}/aports/{rel_in_dir}', f'{url}',
                      f'git blob {blob} of aports commit {commit} ({provider_note})'))
    local = {gpath.split(f'/{comp.name}/', 1)[1]: path for path, gpath, _u, _b in comp.fetch['aports_files']}
    seen = set()
    for carch, ev in sorted((comp.fetch.get('eval') or {}).items()):
        if not ev:
            raise Unresolved(f'APKBUILD evaluation produced no output for {carch}')
        if ev['version'] != comp.version:
            raise VerificationError(f'APKBUILD at {commit} is {ev["version"]}, image has {comp.version}')
        for entry in ev['sources']:
            name, url = source_name(entry)
            if name in seen:
                continue
            seen.add(name)
            want = ev['sha512'].get(name)
            if not want:
                raise Unresolved(f'{name} has no sha512sums entry in the APKBUILD')
            if url is None:
                path = local.get(name)
                if path is None:
                    raise Unresolved(f'local source {name} missing from aports directory')
                got = hashlib.sha512(path.read_bytes()).hexdigest()
                if got != want:
                    raise VerificationError(f'{name}: sha512 {got[:16]} != APKBUILD {want[:16]}')
                continue  # already shipped as part of the aports directory
            branches = []
            for b in (comp.fetch.get('branch') or 'edge', *sorted(comp.fetch.get('other_branches') or ()), 'edge'):
                if b and b not in branches:
                    branches.append(b)
            candidates = [f'{DISTFILES}/{b}/{quote_url(name)}' for b in branches]
            if re.match(r'^(https?|ftp)://', url):
                candidates.append(url)
            path, got_url = cache.fetch(candidates, 'sha512', want)
            files.append((path, f'{base}/distfiles/{name}', got_url,
                          f'sha512 from APKBUILD sha512sums at aports {commit}'))
    return files
