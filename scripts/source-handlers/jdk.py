"""Java runtimes found through their `release` file.

* Eclipse Temurin: the `-jdk-sources` tarball Adoptium attaches to the exact GitHub release
  (verified against the release's `.sha256.txt`), plus the temurin-build scripts at the
  commit recorded in BUILD_SOURCE.
* Red Hat OpenJDK: an RPM; its SRPM is collected by the RPM handler.
* Azul Zulu: Azul does not publish source archives; it offers source on request. Recorded
  as UNRESOLVED so the gap is visible."""
from __future__ import annotations

import re

from common import Component, Unresolved, slug
import gitsrc

ADOPTIUM = 'https://github.com/adoptium/temurin{major}-binaries/releases/download/{tag}/{asset}'


def parse_release(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r'^([A-Z_]+)="?(.*?)"?$', line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def components(facts, image_ref, arch, cache, registry):
    n = 0
    for path, text in sorted((facts.get('jdk_release') or {}).items()):
        rel = parse_release(text)
        impl = rel.get('IMPLEMENTOR', '')
        iv = rel.get('IMPLEMENTOR_VERSION', '')
        if 'Red Hat' in impl:
            continue  # shipped as an RPM: the java-*-openjdk SRPM is collected by rpm.py
        if 'Adoptium' in impl:
            key = f'jdk:temurin@{iv}'
            vendor = 'Eclipse Adoptium Temurin'
        elif 'Azul' in impl:
            key = f'jdk:zulu@{iv}'
            vendor = 'Azul Zulu'
        else:
            key = f'jdk:{slug(impl) or "unknown"}@{iv or rel.get("JAVA_VERSION")}'
            vendor = impl or 'unknown vendor'
        comp = registry.get(key)
        if comp is None:
            comp = Component(key=key, ecosystem='jdk', name=vendor, version=iv or rel.get('JAVA_VERSION', ''),
                             licence='GPL-2.0-only WITH Classpath-exception-2.0 (OpenJDK)',
                             category='copyleft', families=['GPL'])
            comp.fetch = {'release': rel}
            comp.notes.append('the Classpath Exception covers programs linked with the JDK, not the '
                              'JDK itself: its own source must still be provided')
            registry[key] = comp
        comp.add_image(image_ref, arch, f'{path} ({rel.get("IMAGE_TYPE", "")} {rel.get("JAVA_RUNTIME_VERSION", "")}, '
                                        f'LIBC={rel.get("LIBC", "")}, SOURCE={rel.get("SOURCE", "")})')
        n += 1
    return n


def fetch(comp, cache, out_dir, rel_root, workroot):
    rel = comp.fetch['release']
    if comp.key.startswith('jdk:temurin@'):
        m = re.match(r'^Temurin-(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\+(\d+)$', rel.get('IMPLEMENTOR_VERSION', ''))
        if not m:
            raise Unresolved(f'unrecognised Temurin version {rel.get("IMPLEMENTOR_VERSION")}')
        major = m.group(1)
        ver = '.'.join(g for g in m.group(1, 2, 3, 4) if g)
        build = m.group(5)
        tag = f'jdk-{ver}%2B{build}'
        asset = f'OpenJDK{major}U-jdk-sources_{ver}_{build}.tar.gz'
        url = ADOPTIUM.format(major=major, tag=tag, asset=asset)
        sums = cache.cached_get(url + '.sha256.txt', allow_404=True)
        if not sums:
            raise Unresolved(f'Adoptium publishes no {asset}.sha256.txt for {tag}')
        digest = sums.decode().split()[0].lower()
        path, got = cache.fetch([url], 'sha256', digest)
        files = [(path, f'{rel_root}/jdk/temurin-{ver}+{build}/{asset}', got,
                  f'sha256 from Adoptium release asset {asset}.sha256.txt')]
        bs = rel.get('BUILD_SOURCE', '')
        repo = rel.get('BUILD_SOURCE_REPO', '').removesuffix('.git')
        mb = re.match(r'^git:([0-9a-f]{40})$', bs)
        if mb and repo.startswith('https://github.com/'):
            gpath, desc = gitsrc.archive(cache, repo, mb.group(1), workroot)
            files.append((gpath, f'{rel_root}/jdk/temurin-{ver}+{build}/temurin-build-{mb.group(1)[:12]}.tar.gz',
                          f'{repo}@{mb.group(1)}', desc + ' (Temurin build scripts, BUILD_SOURCE)'))
        comp.notes.append(f'SOURCE_REPO {rel.get("SOURCE_REPO")} {rel.get("SOURCE")}')
        return files
    if comp.key.startswith('jdk:zulu@'):
        raise Unresolved('Azul does not publish source archives for Zulu builds; its third-party '
                         'licence document offers the complete source on request (azul_openJDK@azul.com, '
                         'valid three years). The build commit in the release file (SOURCE='
                         f'{rel.get("SOURCE")}) is not in the public OpenJDK repositories. Request the '
                         'source from Azul or switch the image to a JDK whose source is published.')
    raise Unresolved(f'no source location known for JDK vendor {comp.name}')
