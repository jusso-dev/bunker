#!/usr/bin/env python3
"""Download a release, verify it, and delegate installation to its install.py."""
import argparse
import hashlib
import hmac
import io
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = 'jusso-dev/bunker'


def target():
    system, machine = platform.system(), platform.machine().lower()
    targets = {('Linux', 'x86_64'): 'x86_64-unknown-linux-gnu',
               ('Darwin', 'arm64'): 'aarch64-apple-darwin',
               ('Darwin', 'x86_64'): 'x86_64-apple-darwin',
               ('Windows', 'amd64'): 'x86_64-pc-windows-msvc'}
    if (system, machine) not in targets:
        raise ValueError(f'unsupported platform: {system}/{machine}')
    return targets[system, machine]


def fetch(base, name, destination):
    url = urllib.parse.urlsplit(base)
    if pathlib.Path(base).is_dir() or not url.scheme:
        shutil.copyfile(pathlib.Path(base) / name, destination)
    elif url.scheme == 'https':
        with urllib.request.urlopen(base.rstrip('/') + '/' + name, timeout=60) as response:
            if urllib.parse.urlsplit(response.url).scheme != 'https':
                raise ValueError('release download redirected away from HTTPS')
            with destination.open('wb') as output:
                shutil.copyfileobj(response, output)
    else:
        raise ValueError('release base must be HTTPS or an explicit local fixture directory')


def checksum(text, name):
    match = re.fullmatch(r'([0-9a-fA-F]{64})  ' + re.escape(name) + r'\n?', text)
    if not match:
        raise ValueError('invalid release checksum or archive filename')
    return match[1].lower()


def installer(content, windows):
    if windows:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = [e for e in archive.infolist() if e.filename == 'install.py']
            if (len(entries) != 1 or entries[0].is_dir() or entries[0].file_size > 65536
                    or (entries[0].external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError('archive must contain one regular install.py')
            return archive.read(entries[0])
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
        entries = [e for e in archive.getmembers() if e.name == 'install.py']
        if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 65536:
            raise ValueError('archive must contain one regular install.py')
        return archive.extractfile(entries[0]).read()


def bootstrap(version, prefix, release_base=None):
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', version):
        raise ValueError('version must be an explicit release version without the v prefix')
    selected = target()
    windows = 'windows' in selected
    name = f'bunker-{version}-{selected}' + ('.zip' if windows else '.tar.gz')
    base = release_base or f'https://github.com/{REPOSITORY}/releases/download/v{version}'
    with tempfile.TemporaryDirectory(prefix='bunker-bootstrap-') as directory:
        root = pathlib.Path(directory)
        archive, sums = root / name, root / (name + '.sha256')
        fetch(base, name, archive)
        fetch(base, sums.name, sums)
        digest = checksum(sums.read_text(encoding='utf-8'), name)
        content = archive.read_bytes()
        if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), digest):
            raise ValueError('archive checksum mismatch')
        if shutil.which('gh'):
            # Bind provenance to the release tag and packaging workflow, not just the
            # repository, so a mirror cannot substitute another attested build.
            subprocess.run(['gh', 'attestation', 'verify', str(archive), '--repo', REPOSITORY,
                            '--signer-workflow', f'{REPOSITORY}/.github/workflows/packages.yml',
                            '--source-ref', f'refs/tags/v{version}'], check=True)
        else:
            print('gh unavailable: verified SHA-256 only; release provenance was not verified.', file=sys.stderr)
        # Read only the installer member from the bytes already verified. Never extract paths.
        script = root / 'install.py'
        script.write_bytes(installer(content, windows))
        subprocess.run([sys.executable, str(script), '--archive', str(archive),
                        '--sha256', digest, '--prefix', str(prefix)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--prefix', type=pathlib.Path, default=pathlib.Path.home() / '.local')
    parser.add_argument('--release-base', help='HTTPS release mirror or local fixture directory')
    args = parser.parse_args()
    bootstrap(args.version, args.prefix, args.release_base)


if __name__ == '__main__':
    main()
