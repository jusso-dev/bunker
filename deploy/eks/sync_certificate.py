"""Refresh exported ACM TLS material without changing the host signing CA.

Runs under a dedicated EKS Pod Identity. No credentials or private material are
logged. Secret projection is verified before restarting the application.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import ssl
import time
import urllib.request

import boto3
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def kubernetes(method, path, data=None):
    account = Path('/var/run/secrets/kubernetes.io/serviceaccount')
    context = ssl.create_default_context(cafile=str(account / 'ca.crt'))
    request = urllib.request.Request(
        'https://kubernetes.default.svc' + path,
        data=None if data is None else json.dumps(data).encode(),
        headers={'Authorization': 'Bearer ' + (account / 'token').read_text().strip(),
                 'Content-Type': 'application/merge-patch+json'}, method=method,
    )
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        return json.load(response)


def main():
    acm = boto3.client('acm', region_name='ap-southeast-2')
    sm = boto3.client('secretsmanager', region_name='ap-southeast-2')
    arn = os.environ['CERTIFICATE_ARN']
    secret_id = 'bunker-eks-identity'
    issued = acm.get_certificate(CertificateArn=arn)
    leaf = x509.load_pem_x509_certificate(issued['Certificate'].encode())
    serial = format(leaf.serial_number, 'x')
    identity = json.loads(sm.get_secret_value(SecretId=secret_id)['SecretString'])
    chain = issued['Certificate'] + issued['CertificateChain']
    if identity['tls.crt'] != chain:
        password = secrets.token_urlsafe(40).encode()
        exported = acm.export_certificate(CertificateArn=arn, Passphrase=password)
        # ACM could renew between GetCertificate and ExportCertificate.
        leaf = x509.load_pem_x509_certificate(exported['Certificate'].encode())
        serial = format(leaf.serial_number, 'x')
        chain = exported['Certificate'] + exported['CertificateChain']
        key = serialization.load_pem_private_key(exported['PrivateKey'].encode(), password)
        identity['tls.key'] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()).decode()
        identity['tls.crt'] = chain
        # Preserve separately provisioned self-signed probe trust anchors.
        # An ACM export chain may end in a cross-signed root.
        sm.put_secret_value(SecretId=secret_id, SecretString=json.dumps(identity))
    kubernetes('PATCH', '/apis/external-secrets.io/v1/namespaces/bunker/externalsecrets/bunker-identity',
               {'metadata': {'annotations': {'force-sync': str(time.time_ns())}}})
    deadline = time.monotonic() + 120
    while True:
        projected = kubernetes('GET', '/api/v1/namespaces/bunker/secrets/bunker-identity')
        if base64.b64decode(projected.get('data', {}).get('tls.crt', '')).decode() == chain:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('Certificate projection did not finish')
        time.sleep(5)
    deployment_path = '/apis/apps/v1/namespaces/bunker/deployments/bunker-control-plane'
    deployment = kubernetes('GET', deployment_path)
    annotation = 'bunker.yumait.au/tls-serial'
    if deployment['spec']['template']['metadata'].get('annotations', {}).get(annotation) != serial:
        kubernetes('PATCH', deployment_path, {'spec': {'template': {'metadata': {'annotations': {annotation: serial}}}}})
    print('Certificate custody and rollout annotation are current.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Provider and API bodies may contain private detail. Leave diagnosis to
        # access-controlled service health and audit logs, never exception dumps.
        print('Certificate synchronization failed.', flush=True)
        raise SystemExit(1)
