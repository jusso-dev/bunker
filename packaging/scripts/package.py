#!/usr/bin/env python3
"""Build unsigned archives and a conservative source-dependency CycloneDX SBOM."""
import argparse
import hashlib
import json
import pathlib
import platform
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', type=pathlib.Path, default=pathlib.Path('dist'))
    args = parser.parse_args()
    allowed = {'x86_64-unknown-linux-gnu', 'aarch64-apple-darwin',
               'x86_64-apple-darwin', 'x86_64-pc-windows-msvc'}
    if args.target not in allowed:
        parser.error('unsupported package target')
    metadata = json.loads(subprocess.check_output([
        'cargo', 'metadata', '--locked', '--format-version', '1', '--filter-platform', args.target]))
    package = next(p for p in metadata['packages'] if p['name'] == 'bunker' and p['id'] in metadata['workspace_members'])
    binary_name = 'bunker.exe' if 'windows' in args.target else 'bunker'
    binary = pathlib.Path(metadata['target_directory']) / args.target / 'release' / binary_name
    if not binary.is_file():
        parser.error(f'build the release binary for {args.target} first')
    args.output.mkdir(parents=True, exist_ok=True)
    stem = f"bunker-{package['version']}-{args.target}"
    sbom = {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'metadata': {
            'component': {'type': 'application', 'name': 'bunker', 'version': package['version']},
            'properties': [
                {'name': 'bunker:scope', 'value': 'Cargo source dependency inventory; includes build/dev dependencies, not a minimal linked-binary inventory'},
                {'name': 'bunker:target', 'value': args.target},
                {'name': 'bunker:build-host', 'value': platform.platform()},
            ],
        },
        'components': [
            {'type': 'library', 'name': p['name'], 'version': p['version'], 'bom-ref': p['id'],
             **({'licenses': [{'expression': p['license']}]} if p.get('license') else {})}
            for p in sorted(metadata['packages'], key=lambda p: p['id'])
        ],
        'dependencies': [
            {'ref': n['id'], 'dependsOn': sorted(n['dependencies'])}
            for n in metadata['resolve']['nodes']
        ],
    }
    sbom_path = args.output / f'{stem}.cdx.json'
    sbom_path.write_text(json.dumps(sbom, indent=2) + '\n', encoding='utf-8')
    with tempfile.TemporaryDirectory() as directory:
        stage = pathlib.Path(directory)
        shutil.copy2(binary, stage / binary_name)
        (stage / binary_name).chmod(0o755)
        shutil.copy2('LICENSE', stage / 'LICENSE')
        shutil.copy2(sbom_path, stage / 'sbom.cdx.json')
        (stage / 'BUILD.txt').write_text(
            f'Unsigned development package\nTarget: {args.target}\n'
            f"Commit: {subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()}\n"
            'Verify the matching GitHub Actions provenance before installation.\n', encoding='utf-8')
        if 'windows' in args.target:
            archive = args.output / f'{stem}.zip'
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
                for entry in sorted(stage.iterdir()):
                    output.write(entry, entry.name)
        else:
            archive = args.output / f'{stem}.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                for entry in sorted(stage.iterdir()):
                    output.add(entry, arcname=entry.name, recursive=False)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (args.output / f'{archive.name}.sha256').write_text(f'{digest}  {archive.name}\n', encoding='utf-8')
    print(f'Created unsigned archive: {archive}')


if __name__ == '__main__':
    main()
