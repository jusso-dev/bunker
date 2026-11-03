#!/usr/bin/env python3
import hashlib
import io
import os
import pathlib
import tarfile
import tempfile
import unittest
import zipfile
import json
import shutil
import subprocess
import sys
from unittest.mock import patch

from install import install
import bootstrap
import package

SCRIPTS = pathlib.Path(__file__).resolve().parent


class InstallSafety(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='bunker-install-test-')
        self.root = pathlib.Path(self.directory.name)
        self.binary = 'bunker.exe' if os.name == 'nt' else 'bunker'

    def tearDown(self):
        self.directory.cleanup()

    def archive(self, symlink=False):
        archive = self.root / 'package.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            entry = tarfile.TarInfo(self.binary)
            if symlink:
                entry.type = tarfile.SYMTYPE
                entry.linkname = '../outside'
                output.addfile(entry)
            else:
                entry.size = 6
                output.addfile(entry, io.BytesIO(b'binary'))
            # The installer must never extract unrelated, traversal-shaped entries.
            traversal = tarfile.TarInfo('../escaped')
            traversal.size = 4
            output.addfile(traversal, io.BytesIO(b'nope'))
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def test_installs_only_binary_and_ignores_traversal_members(self):
        archive, digest = self.archive()
        result = install(archive, digest, self.root / 'prefix')
        self.assertEqual(result.read_bytes(), b'binary')
        self.assertFalse((self.root / 'escaped').exists())

    def test_wrong_checksum_does_not_create_installation(self):
        archive, digest = self.archive()
        wrong = ('0' if digest[0] != '0' else '1') + digest[1:]
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            install(archive, wrong, self.root / 'prefix')
        self.assertFalse((self.root / 'prefix').exists())

    def test_symlink_binary_rejected(self):
        archive, digest = self.archive(symlink=True)
        with self.assertRaisesRegex(ValueError, 'regular binary'):
            install(archive, digest, self.root / 'prefix')

    def test_zip_install_and_duplicate_rejection(self):
        archive = self.root / 'package.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr(self.binary, b'binary')
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual(install(archive, digest, self.root / 'prefix').read_bytes(), b'binary')
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(archive, 'a') as output:
                output.writestr(self.binary, b'duplicate')
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'regular binary'):
            install(archive, digest, self.root / 'prefix')


class ReleaseBootstrap(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='bunker-release-test-')
        self.root = pathlib.Path(self.directory.name)
        self.release = self.root / 'release'
        self.release.mkdir()
        self.prefix = self.root / 'prefix'
        self.calls = []

    def tearDown(self):
        self.directory.cleanup()

    def fixture(self, selected, unsafe=False):
        windows = 'windows' in selected
        name = f'bunker-1.2.3-{selected}' + ('.zip' if windows else '.tar.gz')
        archive = self.release / name
        entries = {'bunker': b'fixture binary', 'bunker.exe': b'fixture binary',
                   'install.py': (SCRIPTS / 'install.py').read_bytes()}
        if windows:
            with zipfile.ZipFile(archive, 'w') as output:
                for name, content in entries.items():
                    output.writestr(name, content)
                if unsafe:
                    output.writestr('install.py', b'raise Exception("must never execute")')
        else:
            with tarfile.open(archive, 'w:gz') as output:
                for name, content in entries.items():
                    entry = tarfile.TarInfo(name)
                    entry.size = len(content)
                    if unsafe and name == 'install.py':
                        entry.type = tarfile.SYMTYPE
                        entry.linkname = '../outside'
                        output.addfile(entry)
                    else:
                        output.addfile(entry, io.BytesIO(content))
        sums = archive.with_name(archive.name + '.sha256')
        sums.write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
        return archive, sums

    def test_bootstrap_platform_archives_delegate_to_verified_installer(self):
        for selected in ('x86_64-unknown-linux-gnu', 'aarch64-apple-darwin',
                         'x86_64-apple-darwin', 'x86_64-pc-windows-msvc'):
            with self.subTest(target=selected):
                archive, _ = self.fixture(selected)
                real_run = subprocess.run

                def run(args, **kwargs):
                    if args[0] == 'gh':
                        self.calls.append(args)
                        return subprocess.CompletedProcess(args, 0)
                    return real_run(args, **kwargs)

                with patch.object(bootstrap, 'target', return_value=selected), \
                     patch.object(bootstrap.shutil, 'which', return_value='/fake/gh'), \
                     patch.object(bootstrap.subprocess, 'run', side_effect=run):
                    bootstrap.bootstrap('1.2.3', self.prefix, str(self.release))
                binary = 'bunker.exe' if os.name == 'nt' else 'bunker'
                self.assertEqual((self.prefix / 'bin' / binary).read_bytes(), b'fixture binary')
                self.assertEqual(self.calls[-1][1:3], ['attestation', 'verify'])
                self.assertEqual(pathlib.Path(self.calls[-1][3]).name, archive.name)
                self.assertEqual(self.calls[-1][4:], [
                    '--repo', 'jusso-dev/bunker',
                    '--signer-workflow', 'jusso-dev/bunker/.github/workflows/packages.yml',
                    '--source-ref', 'refs/tags/v1.2.3'])

    def test_checksum_and_attestation_fail_before_installer_execution(self):
        archive, sums = self.fixture(bootstrap.target())
        original = sums.read_text()
        sums.write_text('0' * 64 + '  ' + archive.name + '\n')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            bootstrap.bootstrap('1.2.3', self.prefix, str(self.release))
        self.assertFalse(self.prefix.exists())
        sums.write_text(original)
        with patch.object(bootstrap.shutil, 'which', return_value='/fake/gh'), \
             patch.object(bootstrap.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'gh')):
            with self.assertRaises(subprocess.CalledProcessError):
                bootstrap.bootstrap('1.2.3', self.prefix, str(self.release))
        self.assertFalse(self.prefix.exists())

    def test_absent_gh_warns_and_unsafe_installer_member_is_rejected(self):
        self.fixture(bootstrap.target())
        with patch.object(bootstrap.shutil, 'which', return_value=None), \
             patch('sys.stderr', new_callable=io.StringIO) as warning:
            bootstrap.bootstrap('1.2.3', self.prefix, str(self.release))
        self.assertIn('provenance was not verified', warning.getvalue())
        for selected in ('x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc'):
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                archive, _ = self.fixture(selected, unsafe=True)
            with self.assertRaisesRegex(ValueError, 'one regular install.py'):
                bootstrap.installer(archive.read_bytes(), 'windows' in selected)

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is not installed')
    def test_windows_powershell_bootstrap_with_local_release(self):
        archive, sums = self.fixture('x86_64-pc-windows-msvc')
        # A PowerShell function supplies deterministic gh success/failure without network.
        driver = self.root / 'driver.ps1'
        driver.write_text('function gh { $global:LASTEXITCODE = [int]$env:FIXTURE_GH_EXIT; '
                          'Add-Content -LiteralPath $env:FIXTURE_GH_LOG -Value ($args -join " ") }\n'
                          '& $env:FIXTURE_INSTALL -Version 1.2.3 -Prefix $env:FIXTURE_PREFIX '
                          '-ReleaseBase $env:FIXTURE_RELEASE -Python $env:FIXTURE_PYTHON\n')
        log = self.root / 'gh.log'
        env = {**os.environ, 'FIXTURE_GH_EXIT': '0', 'FIXTURE_GH_LOG': str(log),
               'FIXTURE_INSTALL': str(SCRIPTS / 'install.ps1'), 'FIXTURE_PREFIX': str(self.prefix),
               'FIXTURE_RELEASE': str(self.release), 'FIXTURE_PYTHON': sys.executable}
        command = ['pwsh', '-NoProfile', '-File', str(driver)]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.prefix / 'bin' / ('bunker.exe' if os.name == 'nt' else 'bunker')).read_bytes(), b'fixture binary')
        self.assertIn('attestation verify', log.read_text())
        self.assertIn('--repo jusso-dev/bunker --signer-workflow '
                      'jusso-dev/bunker/.github/workflows/packages.yml '
                      '--source-ref refs/tags/v1.2.3', log.read_text())
        shutil.rmtree(self.prefix)
        env['FIXTURE_GH_EXIT'] = '1'
        self.assertNotEqual(subprocess.run(command, env=env, capture_output=True).returncode, 0)
        self.assertFalse(self.prefix.exists())
        log.unlink()
        sums.write_text('0' * 64 + '  ' + archive.name + '\n')
        self.assertNotEqual(subprocess.run(command, env=env, capture_output=True).returncode, 0)
        self.assertFalse(log.exists(), 'checksum failure must precede gh and installation')


class ManifestTemplates(unittest.TestCase):
    def test_render_homebrew_formula(self):
        template = (SCRIPTS.parent / 'manifests/bunker.rb.in').read_text()
        rendered = template.replace('@VERIFIED_RELEASE_ARCHIVE_URL@', 'https://example.test/bunker.tar.gz') \
                           .replace('@VERIFIED_SHA256@', 'a' * 64)
        self.assertNotRegex(rendered, r'@[A-Z_]+@')
        self.assertIn('sha256 "' + 'a' * 64 + '"', rendered)
        if shutil.which('ruby'):
            result = subprocess.run(['ruby', '-c'], input=rendered, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_render_winget_manifest(self):
        import yaml
        template = (SCRIPTS.parent / 'manifests/bunker.winget.yaml.in').read_text()
        rendered = template.replace('@VERSION@', '1.2.3') \
                           .replace('@SIGNED_MSI_URL@', 'https://example.test/bunker.msi') \
                           .replace('@SIGNED_MSI_SHA256@', 'a' * 64)
        self.assertNotRegex(rendered, r'@[A-Z_]+@')
        manifest = yaml.safe_load(rendered)
        self.assertEqual(manifest['PackageVersion'], '1.2.3')
        self.assertEqual(manifest['Installers'][0]['InstallerSha256'], 'a' * 64)
        self.assertEqual(manifest['InstallerType'], 'wix')

    def test_package_contains_the_installer_used_by_bootstraps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            selected = 'x86_64-unknown-linux-gnu'
            binary = root / selected / 'release' / 'bunker'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'fixture binary')
            metadata = {'target_directory': str(root), 'workspace_members': ['bunker-id'],
                        'packages': [{'name': 'bunker', 'id': 'bunker-id', 'version': '1.2.3'}],
                        'resolve': {'nodes': []}}
            dist = root / 'dist'
            with patch.object(sys, 'argv', ['package.py', '--target', selected, '--output', str(dist)]), \
                 patch.object(package.platform, 'platform', return_value='fixture-host'), \
                 patch.object(package.subprocess, 'check_output', side_effect=[json.dumps(metadata).encode(), 'fixture-commit\n']):
                previous = pathlib.Path.cwd()
                try:
                    os.chdir(SCRIPTS.parents[1])
                    package.main()
                finally:
                    os.chdir(previous)
            archive = next(dist.glob('*.tar.gz'))
            self.assertEqual(bootstrap.installer(archive.read_bytes(), False), (SCRIPTS / 'install.py').read_bytes())
            digest = bootstrap.checksum(archive.with_name(archive.name + '.sha256').read_text(), archive.name)
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)



if __name__ == '__main__':
    unittest.main()
