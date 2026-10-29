#!/usr/bin/env python3
"""Install only the binary member from a checksum-verified local package."""
import argparse
import hashlib
import hmac
import os
import pathlib
import re
import tarfile
import tempfile
import zipfile


def install(archive, checksum, prefix):
    if not re.fullmatch(r'[0-9a-fA-F]{64}', checksum):
        raise ValueError('expected a SHA-256 hex digest from a trusted source')
    content = archive.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), checksum.lower()):
        raise ValueError('archive checksum mismatch')
    name = 'bunker.exe' if os.name == 'nt' else 'bunker'
    # Read from the bytes already verified to avoid an archive path race.
    import io
    if zipfile.is_zipfile(io.BytesIO(content)):
        with zipfile.ZipFile(io.BytesIO(content)) as package:
            entries = [item for item in package.infolist() if item.filename == name]
            if len(entries) != 1 or entries[0].is_dir() or entries[0].file_size > 256 * 1024 * 1024:
                raise ValueError('archive must contain one regular binary for this platform')
            mode = entries[0].external_attr >> 16
            if mode & 0o170000 == 0o120000:
                raise ValueError('binary must not be a symlink')
            binary = package.read(entries[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as package:
            entries = [item for item in package.getmembers() if item.name == name]
            if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 256 * 1024 * 1024:
                raise ValueError('archive must contain one regular binary for this platform')
            binary = package.extractfile(entries[0]).read()
    destination = prefix / 'bin'
    destination.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination, delete=False) as output:
            temporary = pathlib.Path(output.name)
            output.write(binary)
        temporary.chmod(0o755)
        os.replace(temporary, destination / name)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination / name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=pathlib.Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--prefix', type=pathlib.Path, default=pathlib.Path.home() / '.local')
    args = parser.parse_args()
    try:
        print(install(args.archive, args.sha256, args.prefix))
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, f'Installation refused: {error}\n')


if __name__ == '__main__':
    main()
