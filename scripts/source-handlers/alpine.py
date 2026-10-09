"""Alpine packages: /lib/apk/db/installed -> aports at the exact build commit.

Each installed package records the aports commit it was built from (`c:`) and its
origin directory (`o:`). The package directory is downloaded from that commit and every
file is checked against the git blob id GitLab reports for that commit's tree. The
APKBUILD's `source=` is evaluated (inside a network-less throwaway container of the image
itself) and each distfile is downloaded and checked against the APKBUILD `sha512sums`."""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import uuid
from pathlib import Path

from common import (Component, Unresolved, VerificationError, classify_expression, http_get,
                    log, quote_url, slug)

GITLAB = 'https://gitlab.alpinelinux.org'
PROJECT = 'alpine%2Faports'
DISTFILES = 'https://distfiles.alpinelinux.org/distfiles'


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


def components(facts, image_ref, arch, cache, registry):
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
            results = [classify_expression(l) for l in licences]
            cat = ('copyleft' if any(r['category'] == 'copyleft' for r in results) else
                   'unknown' if any(r['category'] == 'unknown' for r in results) else
                   'elected-permissive' if any(r['category'] == 'elected-permissive' for r in results)
                   else 'permissive')
            comp = Component(key=key, ecosystem='alpine', name=origin, version=ver,
                             licence=' AND '.join(l for l in licences if l) or '(none declared)',
                             category=cat, families=sorted({f for r in results for f in r['families']}))
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


def aports_tree(cache, origin, commit):
    """Return (repo, entries) for main|community|testing/<origin> at commit."""
    for repo in ('main', 'community', 'testing'):
        data, page = [], 1
        while True:
            url = (f'{GITLAB}/api/v4/projects/{PROJECT}/repository/tree?path={repo}/{quote_url(origin)}'
                   f'&ref={commit}&recursive=true&per_page=100&page={page}')
            try:
                chunk = cache.cached_json(url, allow_404=True)
            except Exception as exc:
                raise Unresolved(f'GitLab tree API failed for {repo}/{origin}@{commit}: {exc}')
            data += chunk or []
            if not chunk or len(chunk) < 100:
                break
            page += 1
        if data:
            return repo, [e for e in data if e['type'] == 'blob']
    raise Unresolved(f'aports commit {commit} has no main|community|testing/{origin}')


def fetch_aports_dir(cache, origin, commit):
    repo, entries = aports_tree(cache, origin, commit)
    files = []
    for e in entries:
        # The web /-/raw/ endpoint sits behind a browser challenge; the API serves blobs by id.
        url = f'{GITLAB}/api/v4/projects/{PROJECT}/repository/blobs/{e["id"]}/raw'
        path = cache.blob('gitblob', e['id'])
        if not path.exists():
            data = http_get(url)
            got = git_blob_sha1(data)
            if got != e['id']:
                raise VerificationError(f'{e["path"]}: git blob {got} != tree entry {e["id"]}')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
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
        work = workroot / f'apkeval-{uuid.uuid4().hex[:10]}'
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


def prepare(comps, cache, workroot):
    """Download aports directories and evaluate their APKBUILDs (batched)."""
    jobs = []
    for comp in comps:
        commit = comp.fetch.get('commit')
        if not commit:
            continue
        try:
            repo, files = fetch_aports_dir(cache, comp.name, commit)
        except (Unresolved, VerificationError) as exc:
            comp.fetch['error'] = exc
            continue
        except Exception as exc:  # network/API failure: report it on the component
            comp.fetch['error'] = Unresolved(f'aports download failed: {type(exc).__name__}: {exc}')
            continue
        comp.fetch['repo'] = repo
        comp.fetch['aports_files'] = files
        apkbuild = next((f[0] for f in files if f[1].endswith(f'/{comp.name}/APKBUILD')), None)
        if not apkbuild:
            comp.fetch['error'] = Unresolved(f'no APKBUILD in {repo}/{comp.name}@{commit}')
            continue
        image_ref, resolved, arch = comp.fetch['eval_image']
        for carch in sorted(comp.fetch['apk_arch']):
            job_id = f'{slug(comp.name)}--{carch}--{uuid.uuid4().hex[:6]}'
            comp.fetch.setdefault('jobs', []).append((job_id, carch))
            jobs.append((job_id, apkbuild, carch, resolved, arch))
    if jobs:
        log(f'evaluating {len(jobs)} APKBUILDs in network-less containers')
        results = evaluate_apkbuilds(jobs, workroot)
        for comp in comps:
            for job_id, carch in comp.fetch.get('jobs', []):
                comp.fetch.setdefault('eval', {})[carch] = results.get(job_id)


def fetch(comp, cache, out_dir, rel_root):
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
        files.append((path, f'{base}/aports/{rel_in_dir}', f'{url}',
                      f'git blob {blob} of aports commit {commit} (GitLab tree)'))
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
            branch = comp.fetch.get('branch') or 'edge'
            candidates = [f'{DISTFILES}/{branch}/{quote_url(name)}', f'{DISTFILES}/edge/{quote_url(name)}']
            if re.match(r'^(https?|ftp)://', url):
                candidates.append(url)
            path, got_url = cache.fetch(candidates, 'sha512', want)
            files.append((path, f'{base}/distfiles/{name}', got_url,
                          f'sha512 from APKBUILD sha512sums at aports {commit}'))
    return files
