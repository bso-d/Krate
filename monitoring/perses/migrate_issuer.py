#!/usr/bin/env python3
"""Migrate the Perses file database when the OIDC issuer changes.

Runs as the one-shot perses-migrate service before Perses and the access guard
start, with no network (network_mode: none) and pure file I/O, as uid 65532 so
it can write the perses_data volume Perses owns.

Perses keys an OIDC identity by its issuer: a user already registered against
one issuer cannot sign in under another ("this user is already registered with a
different oauth provider context"), which locks out every sign-in after the
realm's issuer changes (reproduced in harness/phase4/lab2/logs/100-104). So when
the rendered issuer differs from the one the data was last migrated to, this
removes every OIDC user registered against a different issuer — Perses recreates
the user, against the current issuer, at the next sign-in — and the guard's
managed role bindings, whose names carry an issuer-derived hash (see
perses_sync.binding_names) and are therefore all stale after an issuer change;
the guard recreates each user's binding at their next authenticated request.
Native password users are never touched. The current issuer is then recorded in
.krate-issuer, so a restart without an issuer change does nothing.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

# The access guard's managed bindings (perses_sync.MANAGED). Their names are
# krate-admin-<hash> / krate-viewer-<hash>, the hash derived from issuer+subject,
# so an issuer change orphans every one of them. The guard's own service binding
# (krate-sync) and any operator binding are left alone.
MANAGED_BINDINGS = ('krate-admin-', 'krate-viewer-')
ISSUER_MARKER = '.krate-issuer'


def read_issuer(path):
    """The current issuer, or None when there is no readable rendered issuer.

    A missing or unreadable issuer file means this is not a realm install (the
    renderer only writes it in native mode), so there is nothing to migrate.
    """
    try:
        issuer = Path(path).read_text().strip()
    except OSError:
        return None
    return issuer or None


def is_stale_user(document, issuer):
    """True for an OIDC user registered against an issuer other than the current one.

    A native password user has no oauthProviders and is never stale. An OIDC user
    is stale when none of its providers is the current issuer (Perses users carry
    exactly one OIDC identity, so this is the single old issuer after a change).
    """
    spec = document.get('spec') if isinstance(document, dict) else None
    providers = (spec or {}).get('oauthProviders') or []
    if not isinstance(providers, list) or not providers:
        return False
    issuers = {p.get('issuer') for p in providers if isinstance(p, dict)}
    return issuer not in issuers


def remove_stale_users(data, issuer):
    users = data / 'users'
    if not users.is_dir():
        return 0
    # Classify every user before deleting any: an unreadable file must fail
    # the migration before the marker advances, so a later run re-inspects it
    # instead of taking the marker fast path past a stale-issuer user.
    classified = []
    unreadable = []
    for path in sorted(users.glob('*.json')):
        try:
            document = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            unreadable.append('%s: %s' % (path.name, exc))
            continue
        classified.append((path, is_stale_user(document, issuer)))
    if unreadable:
        raise ValueError('unreadable user file(s), migration not advanced: %s'
                         % '; '.join(unreadable))
    removed = 0
    for path, stale in classified:
        if stale:
            path.unlink()
            removed += 1
    return removed


def remove_managed_bindings(data):
    bindings = data / 'globalrolebindings'
    if not bindings.is_dir():
        return 0
    removed = 0
    for path in sorted(bindings.glob('*.json')):
        if re.fullmatch(r'krate-(admin|viewer)-[0-9a-f]{24}', path.stem):
            path.unlink()
            removed += 1
    return removed


def write_marker(data, issuer):
    marker = data / ISSUER_MARKER
    temporary = marker.with_name(marker.name + '.tmp')
    temporary.write_text(issuer + '\n')
    temporary.chmod(0o400)
    os.replace(temporary, marker)


def migrate(data_dir, issuer):
    data = Path(data_dir)
    marker = data / ISSUER_MARKER
    try:
        applied = marker.read_text().strip() if marker.exists() else None
    except OSError:
        applied = None
    if applied == issuer:
        print('perses-migrate: issuer unchanged (%s); nothing to do' % issuer)
        return 0
    users = remove_stale_users(data, issuer)
    bindings = remove_managed_bindings(data)
    write_marker(data, issuer)
    print('perses-migrate: issuer %s -> %s: removed %d stale user(s) and %d managed binding(s)'
          % (applied or '(none)', issuer, users, bindings))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--issuer-file', default='/etc/krate/perses-migrate/issuer',
                        help='rendered current issuer (read-only)')
    parser.add_argument('--data-dir', default='/perses/data',
                        help='Perses file database folder')
    args = parser.parse_args()
    issuer = read_issuer(args.issuer_file)
    if issuer is None:
        print('perses-migrate: no rendered issuer at %s; not a realm install, nothing to do'
              % args.issuer_file)
        return 0
    try:
        return migrate(args.data_dir, issuer)
    except (OSError, ValueError) as exc:
        print('perses-migrate: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
