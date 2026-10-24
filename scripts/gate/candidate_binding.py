#!/usr/bin/env python3
"""Product byte binding of an installed bundle edition to a candidate commit.

A bundle-host receipt is bound only when the product the bundle installed is the
candidate's.  The inventory is the copy list of the Makefile's `build_one` for the
kraft and epc editions: each installed path maps to the repository path it was copied
from, and every such file is compared byte for byte with that path at the candidate
(`git cat-file`).  `krate` must also be executable.

`make bundle` changes exactly two of those files: it rewrites the `*_IMAGE=` lines of
`.env.template` and `monitoring/.env.template` to the offline runtime tags listed in
the bundle's `images.lock.tsv`.  Those two are compared after replaying that rewrite
(the same field split and substitution as the Makefile's awk) with the installed lock;
the lock's source references must be exactly the images the candidate's two templates
pin, each mapped to `krate-offline/image:sha256-<its image_id>`.  With `--check-images`
the image Docker holds under each runtime tag must have that image id.

`krate install` overlays the release and removes nothing, and the product loads some
directories wholesale (Grafana provisioning and dashboards, the Perses dashboards, the
Python modules beside the sso scripts).  A regular file or symlink in those directories
that the candidate does not ship is therefore a mismatch too; `docs/`, which the bundle
ships, is scanned the same way.  A scanned directory the running user cannot list makes
the comparison fail (exit 2), except a `__pycache__` directory: run it as root (the runner on a
VM does), because a skipped `__pycache__` and the bytecode in it are not compared, and Python can
load an unchecked hash-based `.pyc` without comparing it with its source.

Not compared: file modes other than `krate`'s executable bit, `.bundle-arch`, the image
archives under `images/`, `docker-offline/`, the lock columns after `image_id`
(`repo_digests`, `archive`, `archive_sha256`, `platform`), operator site files (`.env`,
`monitoring/.env` and the `monitoring/.env.*` temporaries of krate's atomic writes,
`auth/` beyond `auth/ui/local.yml`, `monitoring/auth/` beyond `local.ini`, `sso/site*.json`
directly in `sso/`), Python bytecode (`*.pyc` directly in a `__pycache__` directory) and
anything outside the scanned directories (such as the edition's top level beyond the
inventory files).  The image id comparison assumes the build host and this host use the
same Docker image store; with different stores the ids differ and the run is refused.

Output: a first line `PRODUCT_BINDING files=N mismatches=M ...`, then one `MISMATCH`
line per difference, then any `NOTE` lines: an explanation of the differences above (for
example a different Docker image store), not a difference and not counted in M.  Exit codes:
0 everything matches, 1 at least one mismatch, 2 the comparison could not run.  Python 3.9
compatible.
"""
import argparse
import fnmatch
import os
import re
import stat
import subprocess
from typing import Dict, Iterable, List, Optional, Tuple

EDITIONS = ('epc', 'kraft')
# Makefile build_one: cp sso/configure.py ... sso/identity.py "$bundle_dir/sso/"
SSO_FILES = ('configure.py', 'example.json', 'configure-dual.py', 'dual-example.json',
             'activate.sh', 'preflight.py', 'probe.py', 'identity.py', 'idp_watch.py')
# Makefile build_one: cp sso/guides/... "$bundle_dir/docs/"
GUIDES = ('identity-foundation.md', 'dual-login.md', 'pingfederate-sso.md',
          'pingfederate-iam-guide.md', 'sso-flows.md', 'perses-sso.md', 'grafana-sso.md')
# Makefile build_one: the two cp monitoring/... "$bundle_dir/monitoring/" lines
MON_TOP = ('docker-compose.yml', '.env.template', 'seed-alerting.py', 'render.py',
           'grafana-admin.py', 'README.md')
# Makefile build_one: cp -r monitoring/grafana ... monitoring/idp "$bundle_dir/monitoring/"
MON_TREES = ('grafana', 'loki', 'prometheus', 'fluent-bit', 'perses', 'idp')
TEMPLATES = ('.env.template', 'monitoring/.env.template')
LOCK = 'images.lock.tsv'
LOCK_HEADER = ('source_reference', 'runtime_reference', 'image_id')
IMAGE_LINE = re.compile(rb'^[A-Z0-9_]+_IMAGE=')
RUNTIME_PREFIX = 'krate-offline/image:sha256-'
IMAGE_ID = re.compile(r'^sha256:[0-9a-f]{64}$')


def _bytecode(rel: str) -> bool:
    """A Python bytecode file directly in a __pycache__ directory (written beside imported modules)."""
    parts = rel.split('/')
    return len(parts) >= 2 and parts[-2] == '__pycache__' and parts[-1].endswith('.pyc')


def _site_settings(rel: str) -> bool:
    """An operator settings file directly in sso/ (`krate auth configure` reads sso/site*.json)."""
    return os.path.dirname(rel) == 'sso' and fnmatch.fnmatch(os.path.basename(rel), 'site*.json')


def _monitoring_env(rel: str) -> bool:
    """monitoring/.env and the monitoring/.env.* temporaries of krate's atomic .env writes
    (the release packaging excludes the same names)."""
    return rel == 'monitoring/.env' or rel.startswith('monitoring/.env.')


# Directories scanned for files the candidate does not ship: (root, recursive, exclusions).
EXTRA_ROOTS = tuple(('monitoring/' + tree, True, (_bytecode,)) for tree in MON_TREES) + (
    ('sso', True, (_bytecode, _site_settings)),
    ('docs', True, ()),
    ('monitoring', False, (_monitoring_env,)),
)

Mismatch = Tuple[str, str, str]


def _git(repo: str, args: List[str], data: Optional[bytes] = None) -> bytes:
    proc = subprocess.run(['git', '-C', repo] + args, input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        detail = proc.stderr.decode('utf-8', 'replace').strip() or 'exit %d' % proc.returncode
        raise RuntimeError('git %s in %s: %s' % (args[0], repo, detail))
    return proc.stdout


def resolve_commit(repo: str, candidate: str) -> str:
    """The full id of exactly one commit of the checkout."""
    try:
        return _git(repo, ['rev-parse', '--verify', '--quiet', candidate + '^{commit}']).decode().strip()
    except RuntimeError:
        raise RuntimeError('%s is not a commit of %s' % (candidate, repo)) from None


def candidate_blobs(repo: str, candidate: str, sources: Iterable[str]) -> Dict[str, Optional[bytes]]:
    """Bytes of each repository path at the candidate (None when absent or not a file), one git process."""
    names = list(sources)
    request = b''.join(('%s:%s\n' % (candidate, name)).encode('utf-8') for name in names)
    out = _git(repo, ['cat-file', '--batch'], request)
    blobs = {}  # type: Dict[str, Optional[bytes]]
    pos = 0
    for name in names:
        end = out.find(b'\n', pos)
        if end < 0:
            raise RuntimeError('git cat-file --batch output ended before %s' % name)
        header = out[pos:end]
        pos = end + 1
        if header.endswith(b' missing') or header.endswith(b' ambiguous'):
            blobs[name] = None
            continue
        _oid, kind, size_text = header.rsplit(b' ', 2)
        size = int(size_text)
        if len(out) < pos + size + 1 or out[pos + size:pos + size + 1] != b'\n':
            raise RuntimeError('git cat-file --batch output for %s is truncated' % name)
        blobs[name] = out[pos:pos + size] if kind == b'blob' else None
        pos += size + 1
    if pos != len(out):
        raise RuntimeError('git cat-file --batch printed %d unexpected trailing bytes' % (len(out) - pos))
    return blobs


def inventory(repo: str, candidate: str, edition: str) -> Dict[str, str]:
    """Installed path -> repository path: the Makefile build_one copy list of the edition."""
    if edition not in EDITIONS:
        raise ValueError('edition must be one of %s, not %r' % (', '.join(EDITIONS), edition))
    items = {'docker-compose.yml': edition + '/docker-compose.yml'}
    if edition == 'epc':
        items['kafbat.yml'] = 'epc/kafbat.yml'
    items['nginx.conf'] = edition + '/nginx.conf'
    items['LICENSE'] = 'LICENSE'
    items['LICENSE-SOURCES.md'] = 'LICENSE-SOURCES.md'
    items['auth/ui/local.yml'] = edition + '/auth/ui/local.yml'
    for name in SSO_FILES:
        items['sso/' + name] = 'sso/' + name
    items['sso/logrotate/krate-identity.conf'] = 'sso/logrotate/krate-identity.conf'
    for name in GUIDES:
        items['docs/' + name] = 'sso/guides/' + name
    items['krate'] = edition + '/krate'
    for name in MON_TOP:
        items['monitoring/' + name] = 'monitoring/' + name
    trees = ['monitoring/' + tree for tree in MON_TREES] + ['sso/theme']
    listed = _git(repo, ['ls-tree', '-r', '--name-only', '-z', candidate, '--'] + trees)
    for path in listed.decode('utf-8').split('\0'):
        # The bundle prunes __pycache__ directories from the copied trees.
        if path and '/__pycache__/' not in path:
            items[path] = path
    items['monitoring/auth/local.ini'] = 'monitoring/auth/local.ini'
    items['.env.template'] = edition + '/.env.template'
    return items


def template_images(data: bytes) -> List[str]:
    """The *_IMAGE values of a template as the Makefile reads them (awk -F= '{print $2}')."""
    values = []
    for line in data.split(b'\n'):
        if IMAGE_LINE.match(line):
            fields = line.split(b'=')
            values.append(fields[1].decode('utf-8', 'replace'))
    return values


def read_lock(installed: str):
    """The installed lock as (header field tuple, or None when the file is absent,
    {source_reference: (runtime_reference, image_id)})."""
    try:
        with open(os.path.join(installed, LOCK), 'rb') as handle:
            lines = handle.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return None, {}
    if not lines:
        return (), {}
    rows = {}
    for line in lines[1:]:
        if line:
            fields = line.split('\t') + ['', '']
            rows[fields[0]] = (fields[1], fields[2])
    return tuple(lines[0].split('\t')), rows


def replay_rewrite(data: bytes, runtime: Dict[str, str]) -> bytes:
    """The Makefile's awk image rewrite of one template (same field split and substitution;
    awk ends every record with a newline)."""
    lines = data.split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    out = []
    for line in lines:
        if IMAGE_LINE.match(line):
            fields = line.split(b'=')
            value = fields[1].decode('utf-8', 'replace')
            if value in runtime:
                line = fields[0] + b'=' + runtime[value].encode('utf-8')
        out.append(line + b'\n')
    return b''.join(out)


def lock_problems(header, rows: Dict[str, Tuple[str, str]], pinned: Iterable[str]) -> List[str]:
    """Why the lock does not map exactly the candidate's pinned images (header None: no lock file)."""
    if header is None:
        return ['%s missing' % LOCK]
    if header[:3] != LOCK_HEADER:
        return ['%s header is %r, not %s...' % (LOCK, '\t'.join(header), '\t'.join(LOCK_HEADER))]
    expected = set(pinned)
    problems = ['candidate image %s has no lock row' % image for image in sorted(expected - set(rows))]
    problems += ['lock row for %s, which the candidate does not pin' % image for image in sorted(set(rows) - expected)]
    for image in sorted(expected & set(rows)):
        runtime, image_id = rows[image]
        if not IMAGE_ID.match(image_id):
            problems.append('%s has image_id %r, not sha256:<64 hex>' % (image, image_id))
        elif runtime != RUNTIME_PREFIX + image_id[len('sha256:'):]:
            problems.append('%s maps to %r, not %s<its image_id>' % (image, runtime, RUNTIME_PREFIX))
    return problems


def image_problems(rows: Dict[str, Tuple[str, str]]) -> Tuple[List[str], List[str]]:
    """(differences, notes).  The image Docker holds under each runtime tag must carry the lock's image
    id; each tag that does not is a difference.  Rows the lock check refused are not asked about; a daemon
    that cannot be reached is an error (not comparable), not a list of missing images.  A note explains the
    differences, it is not one: it is returned apart so that it is not counted as a mismatch."""
    info = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if info.returncode != 0:
        raise RuntimeError('the Docker daemon cannot be reached (docker info rc %d)' % info.returncode)
    problems = []
    notes = []
    held_ids = differing = absent = 0
    for image in sorted(rows):
        runtime, image_id = rows[image]
        if not IMAGE_ID.match(image_id) or runtime != RUNTIME_PREFIX + image_id[len('sha256:'):]:
            continue  # reported by lock_problems; lock text never reaches the docker command line
        proc = subprocess.run(['docker', 'image', 'inspect', '-f', '{{.Id}}', '--', runtime],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        held = proc.stdout.decode('utf-8', 'replace').strip()
        if proc.returncode != 0:
            problems.append('%s: no image under %s' % (image, runtime))
            absent += 1
            continue
        if held != image_id:
            problems.append('%s: %s holds %s, the lock says %s' % (image, runtime, held, image_id))
        if IMAGE_ID.match(held):  # only a well-formed id can point at the store; an empty answer cannot
            held_ids += 1
            differing += int(held != image_id)
    if held_ids > 1 and differing == held_ids:
        # A containerd image store reports the manifest digest as the image id, the classic store the
        # config digest: when every id differs, the likely cause is not the bundle but the store.
        notes.append('image store: every image this host holds under a runtime tag (%d) has an id that differs from the '
                     'lock; the likely cause is a different Docker image store on the build host and on this host '
                     '(containerd versus classic), which reinstalling the bundle does not change%s'
                     % (held_ids, '; a tag with no image is a separate problem' if absent else ''))
    return problems, notes


def _unlistable(error: OSError) -> None:
    """os.walk error handler: a directory that cannot be listed hides what it holds, so the
    comparison fails (exit 2); a __pycache__ directory only holds another user's bytecode."""
    if os.path.basename(str(error.filename or '')) != '__pycache__':
        raise error


def extra_files(installed: str, items: Dict[str, str]) -> List[str]:
    """Regular files and symlinks in the scanned directories that the candidate does not ship."""
    extras = []
    for root, recursive, excluded in EXTRA_ROOTS:
        base = os.path.join(installed, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base, onerror=_unlistable):
            dirnames.sort()
            names = sorted(filenames) + sorted(d for d in dirnames if os.path.islink(os.path.join(dirpath, d)))
            for name in names:
                rel = os.path.relpath(os.path.join(dirpath, name), installed).replace(os.sep, '/')
                if rel in items or any(rule(rel) for rule in excluded):
                    continue
                extras.append(rel)
            if not recursive:
                break
    return extras


# noinspection PyTypeHints
def compare_installed(repo: str, candidate: str, installed: str, edition: str,
                      check_images: bool = False,
                      notes: Optional[List[str]] = None) -> Tuple[int, List[Mismatch]]:
    """(files compared, mismatches as (installed path, repository path, what differs)).  Explanations of the
    mismatches (not mismatches themselves) are appended to `notes` when a list is passed."""
    items = inventory(repo, candidate, edition)
    blobs = candidate_blobs(repo, candidate, sorted(set(items.values())))
    header, rows = read_lock(installed)
    pinned = []  # type: List[str]
    for installed_rel in TEMPLATES:
        data = blobs.get(items[installed_rel])
        if data is not None:
            pinned += template_images(data)
    lock_source = '%s/.env.template + monitoring/.env.template' % edition
    mismatches = [(LOCK, lock_source, 'lock: ' + problem) for problem in lock_problems(header, rows, pinned)]
    if check_images and rows:
        image_differences, image_notes = image_problems(rows)
        mismatches += [(LOCK, lock_source, 'image: ' + problem) for problem in image_differences]
        if notes is not None:
            notes.extend(image_notes)
    replay_map = {}  # type: Dict[str, str]
    if header and len(header) > 1:
        replay_map[header[0]] = header[1]  # awk reads the header line into its map first
    replay_map.update((source, runtime) for source, (runtime, _image_id) in rows.items())
    for installed_rel in sorted(items):
        source = items[installed_rel]
        path = os.path.join(installed, installed_rel)
        if os.path.islink(path):
            mismatches.append((installed_rel, source, 'a symlink where the bundle installs a file'))
            continue
        try:
            if not stat.S_ISREG(os.stat(path).st_mode):
                mismatches.append((installed_rel, source, 'not a regular file'))
                continue
            with open(path, 'rb') as handle:
                actual = handle.read()
        except OSError as error:
            mismatches.append((installed_rel, source, 'missing: %s' % (error.strerror or error)))
            continue
        expected = blobs.get(source)
        if expected is None:
            mismatches.append((installed_rel, source, 'candidate path missing'))
            continue
        if installed_rel in TEMPLATES:
            expected = replay_rewrite(expected, replay_map)
        if actual != expected:
            mismatches.append((installed_rel, source, 'bytes differ'))
        elif installed_rel == 'krate' and not os.access(path, os.X_OK):
            mismatches.append((installed_rel, source, 'not executable'))
    mismatches += [(rel, '-', 'not in the candidate (extra file in a directory the product loads)')
                   for rel in extra_files(installed, items)]
    return len(items), mismatches


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Compare an installed bundle edition with a candidate commit')
    parser.add_argument('--repo', required=True, help='checkout that holds the candidate commit')
    parser.add_argument('--candidate', required=True, help='candidate commit id')
    parser.add_argument('--installed', required=True, help='installed edition directory, e.g. /opt/krate/epc')
    parser.add_argument('--edition', required=True, choices=EDITIONS)
    parser.add_argument('--check-images', action='store_true',
                        help='also require the image under each runtime tag to carry the lock image id (needs docker)')
    args = parser.parse_args(argv)
    try:
        commit = resolve_commit(args.repo, args.candidate)
        if not os.path.isdir(args.installed):
            raise RuntimeError('installed edition directory %s does not exist' % args.installed)
        notes = []  # type: List[str]
        count, mismatches = compare_installed(args.repo, commit, args.installed, args.edition, args.check_images, notes)
    except Exception as error:  # noqa: BLE001 - any failure means "not comparable" (exit 2), never a traceback
        print('PRODUCT_BINDING error: %s: %s' % (type(error).__name__, error))
        return 2
    print('PRODUCT_BINDING files=%d mismatches=%d candidate=%s installed=%s (Makefile bundle copy list%s; '
          'templates after replaying the image rewrite from %s; extra files in the product directories)'
          % (count, len(mismatches), commit[:12], args.installed,
             '; image ids under the runtime tags' if args.check_images else '', LOCK))
    for installed_rel, source, what in mismatches:
        print('MISMATCH %s <- %s: %s' % (installed_rel, source, what))
    for note in notes:
        print('NOTE %s' % note)
    return 1 if mismatches else 0


if __name__ == '__main__':
    raise SystemExit(main())
