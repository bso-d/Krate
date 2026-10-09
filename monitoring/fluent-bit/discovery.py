#!/usr/bin/env python3
"""Expose only selected Docker log files to tail, without reading their payload."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import uuid

CONTAINER_ID = re.compile(r'[a-f0-9]{64}')
MAX_METADATA = 1024 * 1024


def refresh(docker_root, sources, excluded, generation=None, clean_receipt=True):
    """Admit selected log paths and return (selected, errors).

    A container whose metadata cannot be read keeps its existing source: removing
    a tailed link makes Fluent Bit drop the file offset, so re-admission would
    replay the whole log. Only positively unselected or removed containers are
    pruned. The receipt is written only when clean_receipt allows it.
    """
    docker_root = docker_root.resolve()
    selected = set()
    retained = set()
    errors = 0
    sources.mkdir(parents=True, exist_ok=True)
    # Failure to list the root aborts this cycle without pruning known sources.
    with os.scandir(docker_root) as entries:
        for entry in entries:
            if not CONTAINER_ID.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                continue
            container = Path(entry.path)
            try:
                with (container / 'config.v2.json').open('rb') as stream:
                    raw = stream.read(MAX_METADATA + 1)
                if len(raw) > MAX_METADATA:
                    raise ValueError('metadata exceeds 1 MiB')
                data = json.loads(raw)
            except FileNotFoundError:
                # Docker writes metadata after creating the directory.
                retained.add(entry.name)
                continue
            except (OSError, ValueError, RecursionError) as exc:
                errors += 1
                retained.add(entry.name)
                print('Krate discovery: metadata unavailable for ' + entry.name + ': ' + str(exc), file=sys.stderr)
                continue
            name = data.get('Name') if isinstance(data, dict) else None
            if not isinstance(name, str):
                continue
            name = name.removeprefix('/')
            if name in excluded or not name.startswith(('krate-', 'epc-')):
                continue
            log = container / (entry.name + '-json.log')
            try:
                if not log.is_file():
                    continue
                directory = sources / entry.name
                directory.mkdir(exist_ok=True)
                link = directory / log.name
                if not link.is_symlink() or os.readlink(link) != str(log):
                    temporary = directory / ('.' + log.name)
                    temporary.unlink(missing_ok=True)
                    temporary.symlink_to(log)
                    os.replace(temporary, link)
                selected.add(entry.name)
            except OSError as exc:
                errors += 1
                retained.add(entry.name)
                print('Krate discovery: source unavailable for ' + entry.name + ': ' + str(exc), file=sys.stderr)
    with os.scandir(sources) as entries:
        for entry in entries:
            if (not CONTAINER_ID.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False)
                    or entry.name in selected or entry.name in retained):
                continue
            directory = Path(entry.path)
            try:
                (directory / (entry.name + '-json.log')).unlink(missing_ok=True)
                (directory / ('.' + entry.name + '-json.log')).unlink(missing_ok=True)
                directory.rmdir()
            except OSError as exc:
                errors += 1
                print('Krate discovery: could not prune ' + entry.name + ': ' + str(exc), file=sys.stderr)
    if clean_receipt:
        ready = sources / '.ready.tmp'
        ready.write_text(json.dumps({'updated': time.time(), 'sources': len(selected),
                                     'errors': errors, 'generation': generation}))
        os.replace(ready, sources / '.ready')
    return selected, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-root', type=Path, default=Path('/var/lib/docker/containers'))
    parser.add_argument('--sources', type=Path, default=Path('/sources'))
    parser.add_argument('--generation-file', type=Path, default=Path('/run/krate/discovery-generation'))
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--health', action='store_true')
    parser.add_argument('--interval', type=float, default=5.0)
    # Consecutive erroring cycles before the helper exits, so the restart policy
    # makes a persistent problem visible instead of collecting silently less.
    parser.add_argument('--max-error-cycles', type=int, default=12)
    args = parser.parse_args()
    if args.health:
        try:
            generation = args.generation_file.read_text()
            ready = json.loads((args.sources / '.ready').read_text())
            age = time.time() - ready['updated']
            return 0 if generation and ready.get('generation') == generation and 0 <= age <= 20 else 1
        except (OSError, ValueError, KeyError, TypeError):
            return 1
    excluded = set(os.getenv('KRATE_EXCLUDED_CONTAINERS', '').split(','))
    running = True

    def stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    # The generation marker is on tmpfs, so previous-container readiness cannot
    # pass health even before this process initializes. Publish only after a
    # clean scan, and stop publishing while errors persist.
    args.sources.mkdir(parents=True, exist_ok=True)
    (args.sources / '.ready').unlink(missing_ok=True)
    (args.sources / '.ready.tmp').unlink(missing_ok=True)
    generation = uuid.uuid4().hex
    args.generation_file.parent.mkdir(parents=True, exist_ok=True)
    args.generation_file.write_text(generation)
    clean_once = False
    error_cycles = 0
    while running:
        try:
            _, errors = refresh(args.docker_root, args.sources, excluded, generation,
                                clean_receipt=False)
        except OSError as exc:
            errors = 1
            print('Krate discovery: refresh failed: ' + str(exc), file=sys.stderr)
        error_cycles = error_cycles + 1 if errors else 0
        if not errors:
            clean_once = True
        if clean_once and error_cycles < args.max_error_cycles:
            ready = args.sources / '.ready.tmp'
            ready.write_text(json.dumps({'updated': time.time(), 'errors': errors,
                                         'error_cycles': error_cycles, 'generation': generation}))
            os.replace(ready, args.sources / '.ready')
        else:
            (args.sources / '.ready').unlink(missing_ok=True)
        if args.once:
            return 0 if not errors else 1
        if error_cycles >= args.max_error_cycles:
            print('Krate discovery: errors persisted for ' + str(error_cycles) + ' cycles; exiting', file=sys.stderr)
            return 1
        deadline = time.monotonic() + args.interval
        while running and time.monotonic() < deadline:
            time.sleep(min(0.5, args.interval))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
