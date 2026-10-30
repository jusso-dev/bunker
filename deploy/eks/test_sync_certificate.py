import base64
import datetime as dt
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

spec = importlib.util.spec_from_file_location('sync', Path(__file__).with_name('sync_certificate.py'))
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class CertificateSyncTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture.invalid')])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
                     .serial_number(123).not_valid_before(now - dt.timedelta(days=1))
                     .not_valid_after(now + dt.timedelta(days=30)).sign(self.key, hashes.SHA256())
                     .public_bytes(serialization.Encoding.PEM).decode())
        self.acm = Mock()
        self.acm.get_certificate.return_value = {'Certificate': self.cert, 'CertificateChain': self.cert}
        self.sm = Mock()
        self.identity = {'ca.key': 'fixture-host-ca-must-not-change', 'gateway.secret': 'fixture-gateway',
                         'tls.crt': self.cert + self.cert, 'tls-ca.crt': 'fixture-trust-roots'}
        self.sm.get_secret_value.return_value = {'SecretString': json.dumps(self.identity)}
        self.calls = []

    def kube(self, method, path, data=None):
        self.calls.append((method, path, data))
        if '/secrets/' in path:
            return {'data': {'tls.crt': base64.b64encode((self.cert + self.cert).encode()).decode()}}
        if method == 'GET':
            return {'spec': {'template': {'metadata': {}}}}
        return {}

    def run_sync(self, kube=None):
        with patch.dict(sync.os.environ, {'CERTIFICATE_ARN': 'fixture'}), \
                patch.object(sync.boto3, 'client', side_effect=lambda name, **kw: self.acm if name == 'acm' else self.sm), \
                patch.object(sync, 'kubernetes', side_effect=kube or self.kube):
            sync.main()

    def test_unchanged_secret_repairs_missed_rollout_without_reexport(self):
        self.run_sync()
        self.acm.export_certificate.assert_not_called()
        self.sm.put_secret_value.assert_not_called()
        self.assertTrue(any(method == 'PATCH' and '/deployments/' in path for method, path, _ in self.calls))

    def test_renewed_tls_preserves_other_identity_fields(self):
        self.identity['tls.crt'] = 'old-fixture'
        self.sm.get_secret_value.return_value = {'SecretString': json.dumps(self.identity)}
        self.acm.export_certificate.side_effect = lambda **kw: {
            'Certificate': self.cert, 'CertificateChain': self.cert,
            'PrivateKey': self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.BestAvailableEncryption(kw['Passphrase'])).decode(),
        }
        self.run_sync()
        saved = json.loads(self.sm.put_secret_value.call_args.kwargs['SecretString'])
        self.assertEqual(saved['ca.key'], self.identity['ca.key'])
        self.assertEqual(saved['gateway.secret'], self.identity['gateway.secret'])
        self.assertEqual(saved['tls-ca.crt'], self.identity['tls-ca.crt'])
        parsed = serialization.load_pem_private_key(saved['tls.key'].encode(), None)
        self.assertEqual(parsed.public_key().public_numbers(), self.key.public_key().public_numbers())

    def test_failed_projection_never_restarts_application(self):
        def fail(method, path, data=None):
            if '/secrets/' in path:
                raise RuntimeError('fixture projection failure')
            return self.kube(method, path, data)
        with self.assertRaises(RuntimeError):
            self.run_sync(fail)
        self.assertFalse(any('/deployments/' in path for _, path, _ in self.calls))


if __name__ == '__main__':
    unittest.main()
