#!/usr/bin/env python3
"""Build the pinned Kafbat native authentication and frontend patches into an offline-deployable image.

Requires an online build host with Git, Node.js (upstream recommends 22), npm,
Python 3 and Docker. No compiler/package downloads occur on the deployed VM.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REVISION = 'afc9c918e13c4422268a3a5b7933c7b448746c82'
REPOSITORY = 'https://github.com/kafbat/kafka-ui.git'
BASE_IMAGE = 'kafbat/kafka-ui:v1.5.0@sha256:7cda86a33344160309fdb65146332e4da65db81a945614f2fe32e210803f6fd1'
# Runtime base: Temurin publishes its JDK source; upstream's Azul Zulu base does not.
RUNTIME_IMAGE = 'eclipse-temurin:25-jre-alpine@sha256:3c0a9084927a221ccd1d007fcaf614465672c0af37aaa834c5184483afe56d61'
RUNTIME_PACKAGES = ('gcompat', 'tzdata')  # upstream's apk add list
IMAGE = 'krate/kafka-ui:1.5.0-sso.7'
JDK_IMAGE = 'eclipse-temurin:25-jdk@sha256:119a3d18f160a3e7655a66034d0f43beee31cd7b3b9142d57a5de29772011de6'
LOMBOK_SHA256 = '3488a4e9994c26596baaceebee58cad36a50e3bdaec5be72b5834d3c3b560306'
AUTH_PATCH = ROOT / 'kafbat-ui/native-auth.patch'
GENERATOR_SHA256 = 'f29d9d715a0d67cf1457d918ae7ed33f02d7fb2730c018d246a8d4a93d5ba7e1'
PATCH = ROOT / 'kafbat-ui/native-login.patch'
PNPM = ['npm', 'exec', '--yes', '--package=pnpm@10.26.1', '--', 'pnpm']


def run(*args, cwd=None, capture=False, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, check=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def patch_jar(original, output, assets, classes):
    """Replace only static assets and the explicitly compiled authentication classes."""
    prefix = 'BOOT-INF/classes/static/'
    replacements = {'BOOT-INF/classes/' + p.relative_to(classes).as_posix(): p
                    for p in classes.rglob('*.class')}
    allowed = ('io/kafbat/ui/config/auth/NativeLoginSupport',
               'io/kafbat/ui/config/auth/OAuthSecurityConfig')
    assert replacements and all(name.removeprefix('BOOT-INF/classes/').split('$')[0].removesuffix('.class')
                                in allowed for name in replacements)
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(output, 'w') as target:
        for entry in source.infolist():
            if not entry.filename.startswith(prefix) and entry.filename not in replacements:
                target.writestr(entry, source.read(entry))
        for name, path in replacements.items():
            target.write(path, name, compress_type=zipfile.ZIP_DEFLATED)
        for path in sorted(assets.rglob('*')):
            if path.is_file():
                target.write(path, prefix + path.relative_to(assets).as_posix(),
                             compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(output) as target:
        for entry in source.infolist():
            if not entry.filename.startswith(prefix) and entry.filename not in replacements:
                assert source.read(entry) == target.read(entry.filename), entry.filename
    print('Verified: all entries outside the frontend and two patched authentication classes are unchanged.', flush=True)


def fetch_runtime_packages(arch, directory):
    """Download the upstream runtime packages the Temurin image lacks, for its own Alpine release."""
    if directory.exists():
        shutil.rmtree(directory)  # Only disposable output created by this builder.
    directory.mkdir()
    # Packages and dependencies apk would install or upgrade; ones already present are skipped.
    script = ('set -eu; '
              'names=$(apk add --simulate --no-cache "$@" | sed -nE "s/^[(][0-9]+[/][0-9]+[)] (Installing|Upgrading) ([^ ]+) .*/\\2/p"); '
              'test -n "$names"; apk fetch --no-cache -o /out $names; chown -R "$OWNER" /out')
    run('docker', 'run', '--rm', '--pull=never', '--platform', 'linux/' + arch, '--user', '0',
        '-e', f'OWNER={os.getuid()}:{os.getgid()}', '-v', f'{directory.resolve()}:/out',
        '--entrypoint', 'sh', RUNTIME_IMAGE, '-c', script, 'fetch', *RUNTIME_PACKAGES)
    packages = sorted(directory.glob('*.apk'))
    if not any(p.name.startswith('gcompat-') for p in packages):
        raise ValueError('gcompat was not fetched for the runtime image')
    return [{'file': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in packages]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--source', type=Path, help='Optional existing pinned upstream checkout')
    args = parser.parse_args()
    output = ROOT / 'dist/kafbat-ui' / args.arch
    output.mkdir(parents=True, exist_ok=True)
    source = args.source.resolve() if args.source else output / 'upstream'
    if not source.exists():
        run('git', 'clone', '--depth', '1', '--branch', 'v1.5.0', REPOSITORY, str(source))
    revision = run('git', 'rev-parse', 'HEAD', cwd=source, capture=True)
    if revision != REVISION:
        raise ValueError(f'Refusing unexpected Kafbat revision: {revision}')
    for patch in (PATCH, AUTH_PATCH):
        applied = subprocess.run(['git', 'apply', '--reverse', '--check', str(patch)],
                                 cwd=source, capture_output=True).returncode == 0
        if not applied:
            run('git', 'apply', '--check', str(patch), cwd=source)
            run('git', 'apply', str(patch), cwd=source)
    # Fail if the base image has the wrong architecture; downloading is build-time only.
    inspect = subprocess.run(['docker', 'image', 'inspect', BASE_IMAGE, '--format',
                              '{{.Architecture}}'], capture_output=True, text=True)
    if inspect.returncode or inspect.stdout.strip() != args.arch:
        run('docker', 'pull', '--platform', 'linux/' + args.arch, BASE_IMAGE)
    inspect = subprocess.run(['docker', 'image', 'inspect', RUNTIME_IMAGE, '--format',
                              '{{.Architecture}}'], capture_output=True, text=True)
    if inspect.returncode or inspect.stdout.strip() != args.arch:
        run('docker', 'pull', '--platform', 'linux/' + args.arch, RUNTIME_IMAGE)
    frontend = source / 'frontend'
    schema = source / 'contract-typespec/api'
    run(*PNPM, 'install', '--frozen-lockfile', '--ignore-scripts', cwd=frontend)
    run(*PNPM, 'install', '--frozen-lockfile', '--ignore-scripts', cwd=schema)
    run(str(schema / 'node_modules/.bin/tsp'), 'compile', '.', cwd=schema)
    generator = source / 'openapi-generator.jar'
    if not generator.exists():
        urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/org/openapitools/'
                                   'openapi-generator-cli/5.3.0/openapi-generator-cli-5.3.0.jar', generator)
    if hashlib.sha256(generator.read_bytes()).hexdigest() != GENERATOR_SHA256:
        raise ValueError('OpenAPI generator checksum mismatch')
    run('docker', 'run', '--rm', '--pull=never', '--network', 'none', '--user', '0',
        '--platform', 'linux/' + args.arch, '-v', f'{source}:/work', '--entrypoint', 'java',
        BASE_IMAGE, '-jar', '/work/openapi-generator.jar', 'generate', '-g', 'typescript-fetch',
        '-i', '/work/contract-typespec/build/tsp/api/openapi.yaml',
        '-o', '/work/frontend/src/generated-sources',
        '--additional-properties=enumPropertyNaming=UPPERCASE,typescriptThreePlus=true,'
        'supportsES6=true,nullSafeAdditionalProps=true,withInterfaces=true', '--type-mappings', 'object=any')
    bin_dir = frontend / 'node_modules/.bin'
    run(str(bin_dir / 'tsc'), '--noEmit', cwd=frontend)
    run(str(bin_dir / 'eslint'), 'src/components/AuthPage', 'src/components/NavBar/UserInfo',
        'src/lib/csrf.ts', 'src/lib/__tests__', 'src/lib/constants.ts', 'src/lib/hooks/api/appConfig.ts',
        cwd=frontend)
    run(str(bin_dir / 'jest'), '--runInBand', '--watch=false', '--coverage=false',
        'src/components/AuthPage/SignIn/BasicSignIn/__tests__', 'src/components/NavBar/UserInfo/__tests__',
        'src/lib/__tests__', cwd=frontend)
    run(str(bin_dir / 'vite'), 'build', cwd=frontend,
        env=dict(os.environ, VITE_TAG='v1.5.0-sso.7', VITE_COMMIT=REVISION[:8] + '-sso'))
    context = output / 'image'
    context.mkdir(exist_ok=True)
    original = output / 'upstream-api.jar'
    container = run('docker', 'create', '--platform', 'linux/' + args.arch, BASE_IMAGE, capture=True)
    try:
        run('docker', 'cp', container + ':/api.jar', str(original))
    finally:
        run('docker', 'rm', container)
    java = output / 'java'
    java.mkdir(exist_ok=True)
    with zipfile.ZipFile(original) as jar:
        for name in jar.namelist():
            if name.startswith(('BOOT-INF/classes/', 'BOOT-INF/lib/')):
                jar.extract(name, java)
    lombok = java / 'lombok.jar'
    if not lombok.exists():
        urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/org/projectlombok/'
                                   'lombok/1.18.42/lombok-1.18.42.jar', lombok)
    if hashlib.sha256(lombok.read_bytes()).hexdigest() != LOMBOK_SHA256:
        raise ValueError('Lombok checksum mismatch')
    classes = java / 'classes'
    if classes.exists():
        shutil.rmtree(classes)  # Only disposable output created by this builder.
    classes.mkdir()
    inspect = subprocess.run(['docker', 'image', 'inspect', JDK_IMAGE], capture_output=True)
    if inspect.returncode:
        run('docker', 'pull', JDK_IMAGE)
    run('docker', 'run', '--rm', '--pull=never', '--network=none',
        '-v', f'{java.resolve()}:/build', '-v', f'{source}:/source:ro', JDK_IMAGE,
        'javac', '--release', '25', '-cp', '/build/BOOT-INF/classes:/build/BOOT-INF/lib/*:/build/lombok.jar',
        '-processorpath', '/build/lombok.jar', '-d', '/build/classes',
        *['/source/api/src/main/java/' + name for name in (
            'io/kafbat/ui/config/auth/NativeLoginSupport.java',
            'io/kafbat/ui/config/auth/OAuthSecurityConfig.java')])
    patch_jar(original, context / 'api.jar', frontend / 'build/vite/static', classes)
    shutil.copyfile(source / 'LICENSE', context / 'LICENSE')
    notice = source / 'NOTICE'
    (context / 'upstream-NOTICE').write_text(notice.read_text() if notice.exists() else
        'Based on kafbat/kafka-ui v1.5.0. Original project: https://github.com/kafbat/kafka-ui\n'
        'Modifies login presentation and hardens native OIDC authentication (CSRF, POST logout,\n'
        'ID token claim validation, required role mapping, back-channel logout).\n')
    shutil.copyfile(PATCH, context / PATCH.name)
    shutil.copyfile(AUTH_PATCH, context / AUTH_PATCH.name)
    if f'ARG KRATE_RUNTIME_IMAGE={RUNTIME_IMAGE}\n' not in (ROOT / 'kafbat-ui/Dockerfile').read_text():
        raise ValueError('kafbat-ui/Dockerfile runtime image does not match RUNTIME_IMAGE')
    runtime_packages = fetch_runtime_packages(args.arch, context / 'apk')
    (context / 'provenance.json').write_text(json.dumps({
        'upstream': REPOSITORY, 'revision': REVISION, 'base_image': BASE_IMAGE,
        'base_image_id': run('docker', 'image', 'inspect', BASE_IMAGE, '--format', '{{.Id}}', capture=True),
        'patch_sha256': hashlib.sha256(PATCH.read_bytes()).hexdigest(),
        'auth_patch_sha256': hashlib.sha256(AUTH_PATCH.read_bytes()).hexdigest(),
        'runtime_image': RUNTIME_IMAGE,
        'runtime_image_id': run('docker', 'image', 'inspect', RUNTIME_IMAGE, '--format', '{{.Id}}', capture=True),
        'runtime_packages': runtime_packages,
        'jdk_image': JDK_IMAGE, 'lombok_sha256': LOMBOK_SHA256,
        'generator_sha256': GENERATOR_SHA256, 'architecture': args.arch,
        'node': run('node', '--version', capture=True), 'image': IMAGE,
    }, indent=2) + '\n')
    run('docker', 'build', '--network=none', '--platform', 'linux/' + args.arch,
        '-f', str(ROOT / 'kafbat-ui/Dockerfile'), '-t', IMAGE, str(context))
    image_id = run('docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}', capture=True)
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise ValueError(f'Invalid local image ID: {image_id}')
    # Docker resolves this local reference by the exact built image ID. The
    # bundle retags it for the offline VM and records the archive checksum.
    local_ref = f'{IMAGE}@{image_id}'
    for variant in ('kraft', 'epc'):
        template = ROOT / variant / '.env.template'
        data, count = re.subn(r'^KAFKA_UI_IMAGE=.*$', f'KAFKA_UI_IMAGE={local_ref}',
                              template.read_text(), count=1, flags=re.MULTILINE)
        if count != 1:
            raise ValueError(f'Cannot set KAFKA_UI_IMAGE in {template}')
        template.write_text(data)
    print(f'Built {local_ref} ({args.arch}). Ready for the offline EPC and Krate bundles.', flush=True)


if __name__ == '__main__':
    main()
