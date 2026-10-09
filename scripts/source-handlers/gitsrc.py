"""Exact source trees from git, identified by commit id.

`archive()` fetches a single commit into a cached bare repository (git checks every
object against its id, so the commit id pins the whole tree) and writes a reproducible
tar.gz of that tree. It does not honour export-ignore attributes: the archive is the
complete tree of the commit."""
from __future__ import annotations

import gzip
import io
import os
import re
import subprocess
import tarfile
import uuid
from pathlib import Path

from common import Unresolved, http_json, log, run, slug


def _bare(cache, repo):
    path = Path(cache.root) / 'git' / (slug(repo.split('://', 1)[-1]) + '.git')
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        run('git', 'init', '-q', '--bare', path)
        run('git', '-C', path, 'remote', 'add', 'origin', repo)
    return path


def _gh_headers():
    tok = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    return {'Authorization': f'Bearer {tok}'} if tok else {}


def resolve(cache, repo, rev):
    """Full commit id for a commit id, short id or tag name."""
    if re.fullmatch(r'[0-9a-f]{40}', rev):
        return rev
    if re.fullmatch(r'[0-9a-f]{7,39}', rev):
        m = re.match(r'https://github\.com/([^/]+/[^/]+)', repo)
        if m:
            try:
                data = http_json(f'https://api.github.com/repos/{m.group(1)}/commits/{rev}',
                                 headers=_gh_headers())
                return data['sha']
            except Exception as exc:
                raise Unresolved(f'cannot expand short commit {rev} in {repo}: {exc}')
        raise Unresolved(f'cannot expand short commit {rev} in {repo}')
    proc = subprocess.run(['git', 'ls-remote', repo, f'refs/tags/{rev}', f'refs/tags/{rev}^{{}}'],
                          capture_output=True, text=True, timeout=120)
    refs = dict(reversed(line.split('\t')) for line in proc.stdout.splitlines() if '\t' in line)
    commit = refs.get(f'refs/tags/{rev}^{{}}') or refs.get(f'refs/tags/{rev}')
    if not commit:
        raise Unresolved(f'tag {rev} not found in {repo}')
    return commit


def has_commit(bare, commit):
    return subprocess.run(['git', '-C', bare, 'cat-file', '-e', f'{commit}^{{commit}}'],
                          capture_output=True).returncode == 0


def archive(cache, repo, commit, workroot: Path):
    """Return (cached tar.gz path, verification text) for the complete tree of commit."""
    key = f'gitarchive:{repo}@{commit}'
    marker = cache.meta_path(key)
    if marker.exists():
        p = Path(marker.read_text())
        if p.exists():
            return p, f'complete tree of git commit {commit} fetched by id from {repo}'
    bare = _bare(cache, repo)
    if not has_commit(bare, commit):
        log(f'git fetch {repo} {commit[:12]}')
        proc = subprocess.run(['git', '-C', bare, 'fetch', '-q', '--depth', '1', 'origin', commit],
                              capture_output=True, text=True, timeout=3600)
        if proc.returncode or not has_commit(bare, commit):
            raise Unresolved(f'git fetch {commit} from {repo} failed: {proc.stderr.strip()[-300:]}')
    ctime = int(run('git', '-C', bare, 'show', '-s', '--format=%ct', commit))
    name = repo.rstrip('/').rsplit('/', 1)[-1].removesuffix('.git')
    prefix = f'{name}-{commit[:12]}'
    tmp = Path(cache.root) / 'tmp' / f'{uuid.uuid4().hex}.tar.gz'
    # ls-tree gives mode, type, id and path for every entry of the commit's tree.
    listing = subprocess.run(['git', '-C', bare, 'ls-tree', '-r', '-z', '--full-tree', commit],
                             capture_output=True, check=True).stdout
    entries = []
    for rec in listing.split(b'\0'):
        if not rec:
            continue
        meta, path = rec.split(b'\t', 1)
        mode, typ, oid = meta.decode().split()
        entries.append((path.decode('utf-8', 'surrogateescape'), mode, typ, oid))
    entries.sort()
    cat = subprocess.Popen(['git', '-C', bare, 'cat-file', '--batch'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE)
    with open(tmp, 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as gz, \
            tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for path, mode, typ, oid in entries:
            if typ == 'commit':  # submodule: record as an empty directory, as git archive does
                info = tarfile.TarInfo(f'{prefix}/{path}')
                info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, ctime
                tar.addfile(info)
                continue
            cat.stdin.write(oid.encode() + b'\n')
            cat.stdin.flush()
            header = cat.stdout.readline().split()
            size = int(header[2])
            data = cat.stdout.read(size)
            cat.stdout.read(1)
            info = tarfile.TarInfo(f'{prefix}/{path}')
            info.mtime, info.uid, info.gid, info.uname, info.gname = ctime, 0, 0, 'root', 'root'
            if mode == '120000':
                info.type, info.linkname, info.mode = tarfile.SYMTYPE, data.decode('utf-8', 'surrogateescape'), 0o777
                tar.addfile(info)
            else:
                info.size, info.mode = size, 0o755 if mode == '100755' else 0o644
                tar.addfile(info, io.BytesIO(data))
    cat.stdin.close()
    cat.wait()
    path, _digest = cache.adopt(tmp)
    marker.write_text(str(path))
    return path, f'complete tree of git commit {commit} fetched by id from {repo}'
