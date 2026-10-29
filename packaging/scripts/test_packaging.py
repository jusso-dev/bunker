#!/usr/bin/env python3
import hashlib
import io
import os
import pathlib
import tarfile
import tempfile
import unittest
import zipfile

from install import install


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


if __name__ == '__main__':
    unittest.main()
