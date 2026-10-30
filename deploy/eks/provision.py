#!/usr/bin/env python3
"""Provision Bunker's dedicated EKS dependencies; never print secret material.

Run with boto3 and cryptography installed. AWS_PROFILE selects credentials.
This creates resources only for Bunker and never alters other applications.
"""
import argparse
import base64
import datetime as dt
import json
import secrets
import urllib.request

import boto3
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REGION = "ap-southeast-2"
ACCOUNT = "959038055523"
DB = "bunker-eks-postgres"
IDENTITY = "bunker-eks-identity"
TAGS = [{"Key": "Application", "Value": "bunker"}]
session = boto3.Session(region_name=REGION)


def client(name):
    return session.client(name)


def get_secret(name):
    try:
        return json.loads(client("secretsmanager").get_secret_value(SecretId=name)["SecretString"])
    except client("secretsmanager").exceptions.ResourceNotFoundException:
        return None


def put_new_secret(name, value):
    current = get_secret(name)
    if current is not None:
        return current
    client("secretsmanager").create_secret(Name=name, SecretString=json.dumps(value), Tags=TAGS)
    return value


def prepare():
    ecr = client("ecr")
    for repository in ["bunker/control-plane", "bunker/operations"]:
        try:
            ecr.describe_repositories(repositoryNames=[repository])
        except ecr.exceptions.RepositoryNotFoundException:
            ecr.create_repository(repositoryName=repository, imageTagMutability="IMMUTABLE",
                                  imageScanningConfiguration={"scanOnPush": True}, tags=TAGS)
    ec2 = client("ec2")
    groups = ec2.describe_security_groups(Filters=[
        {"Name": "group-name", "Values": ["bunker-eks-postgres"]},
        {"Name": "vpc-id", "Values": ["vpc-0386855f644985706"]},
    ])["SecurityGroups"]
    if groups:
        sg = groups[0]["GroupId"]
    else:
        sg = ec2.create_security_group(GroupName="bunker-eks-postgres", Description="Bunker PostgreSQL from EKS nodes only",
                                      VpcId="vpc-0386855f644985706", TagSpecifications=[{"ResourceType": "security-group", "Tags": TAGS}])["GroupId"]
    try:
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
            "UserIdGroupPairs": [{"GroupId": "sg-0734dfd23aa10d956", "Description": "yumait-prod EKS nodes and pods"}],
        }])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPermission.Duplicate":
            raise
    credentials = put_new_secret("bunker-eks-db-credentials", {
        "admin_password": secrets.token_urlsafe(40), "app_password": secrets.token_urlsafe(40),
    })
    rds = client("rds")
    try:
        instance = rds.describe_db_instances(DBInstanceIdentifier=DB)["DBInstances"][0]
    except rds.exceptions.DBInstanceNotFoundFault:
        instance = rds.create_db_instance(
            DBInstanceIdentifier=DB, DBName="bunker", DBInstanceClass="db.t4g.micro", Engine="postgres", EngineVersion="17.9",
            MasterUsername="bunker_admin", MasterUserPassword=credentials["admin_password"],
            AllocatedStorage=20, MaxAllocatedStorage=100, StorageType="gp3", StorageEncrypted=True,
            DBSubnetGroupName="yumait-eks-data", VpcSecurityGroupIds=[sg], PubliclyAccessible=False,
            MultiAZ=False, BackupRetentionPeriod=7, DeletionProtection=True,
            AutoMinorVersionUpgrade=True, CopyTagsToSnapshot=True, Tags=TAGS,
        )["DBInstance"]
    acm = client("acm")
    certificates = [c for page in acm.get_paginator("list_certificates").paginate()
                    for c in page["CertificateSummaryList"] if c["DomainName"] == "bunker.yumait.au"]
    if certificates:
        arn = certificates[0]["CertificateArn"]
        description = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        if description.get("Options", {}).get("Export") != "ENABLED":
            raise RuntimeError("Existing Bunker certificate is not exportable; refusing replacement")
    else:
        arn = acm.request_certificate(DomainName="bunker.yumait.au", SubjectAlternativeNames=["hosts.bunker.yumait.au"],
                                     ValidationMethod="DNS", KeyAlgorithm="EC_prime256v1", IdempotencyToken="bunkereks20261030",  # gitleaks:allow -- public request deduplication ID
                                     Options={"CertificateTransparencyLoggingPreference": "ENABLED", "Export": "ENABLED"}, Tags=TAGS)["CertificateArn"]
    print(json.dumps({"database": DB, "database_status": instance["DBInstanceStatus"], "security_group": sg,
                      "certificate_arn": arn, "image_repository": f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/bunker/control-plane"}))


def finish(certificate_arn):
    instance = client("rds").describe_db_instances(DBInstanceIdentifier=DB)["DBInstances"][0]
    if instance["DBInstanceStatus"] not in {"available", "backing-up"} or "Endpoint" not in instance:
        raise RuntimeError("Database is not yet available")
    credentials = get_secret("bunker-eks-db-credentials")
    endpoint = instance["Endpoint"]["Address"]
    suffix = f"@{endpoint}:5432/bunker?sslmode=verify-full&sslrootcert=/run/secrets/bunker/rds-ca.pem"
    put_new_secret("bunker-eks-database", {"database-url": f"postgresql://bunker_app:{credentials['app_password']}" + suffix})
    put_new_secret("bunker-eks-db-admin", {"admin-url": f"postgresql://bunker_admin:{credentials['admin_password']}" + suffix,
                                         "app-password": credentials["app_password"]})
    identity = get_secret(IDENTITY)
    if identity is None:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bunker yumait-prod host signing CA")])
        now = dt.datetime.now(dt.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                       .not_valid_after(now + dt.timedelta(days=3650))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                       .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                                   data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                                   crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                       .sign(key, hashes.SHA256()))
        identity = {"ca.key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()).decode(),
                    "ca.crt": certificate.public_bytes(serialization.Encoding.PEM).decode(),
                    "gateway.secret": base64.b64encode(secrets.token_bytes(32)).decode(), "providers.json": "[]"}
        with urllib.request.urlopen("https://truststore.pki.rds.amazonaws.com/ap-southeast-2/ap-southeast-2-bundle.pem", timeout=30) as response:
            identity["rds-ca.pem"] = response.read(65536).decode()
    passphrase = secrets.token_urlsafe(40).encode()
    exported = client("acm").export_certificate(CertificateArn=certificate_arn, Passphrase=passphrase)
    key = serialization.load_pem_private_key(exported["PrivateKey"].encode(), passphrase)
    identity["tls.key"] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()).decode()
    identity["tls.crt"] = exported["Certificate"] + exported["CertificateChain"]
    # ACM chains can end at a cross-signed Amazon root, not a self-signed trust
    # anchor. Verified probes need the actual roots rather than that chain.
    roots = []
    for number in range(1, 5):
        with urllib.request.urlopen(f"https://www.amazontrust.com/repository/AmazonRootCA{number}.pem", timeout=30) as response:
            roots.append(response.read(16384).decode())
    identity["tls-ca.crt"] = "\n".join(roots)
    if get_secret(IDENTITY) is None:
        put_new_secret(IDENTITY, identity)
    else:
        client("secretsmanager").put_secret_value(SecretId=IDENTITY, SecretString=json.dumps(identity))
    print(json.dumps({"database_endpoint": endpoint, "identity_secret": IDENTITY, "certificate_synced": True}))
    iam = client("iam")
    role_name = "bunker-eks-certificate-sync"
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "pods.eks.amazonaws.com"}, "Action": ["sts:AssumeRole", "sts:TagSession"],
        "Condition": {"StringEquals": {"aws:RequestTag/kubernetes-namespace": "bunker",
                                       "aws:RequestTag/kubernetes-service-account": "bunker-certificate-sync"}}}]}
    try:
        role = iam.get_role(RoleName=role_name)["Role"]
    except iam.exceptions.NoSuchEntityException:
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=TAGS)["Role"]
    secret_arn = client("secretsmanager").describe_secret(SecretId=IDENTITY)["ARN"]
    iam.put_role_policy(RoleName=role_name, PolicyName="BunkerCertificateCustody", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["acm:GetCertificate", "acm:ExportCertificate"], "Resource": certificate_arn},
            {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"], "Resource": secret_arn},
        ]}))
    eks = client("eks")
    associations = eks.list_pod_identity_associations(clusterName="yumait-prod", namespace="bunker",
                                                       serviceAccount="bunker-certificate-sync")["associations"]
    if not associations:
        eks.create_pod_identity_association(clusterName="yumait-prod", namespace="bunker",
                                           serviceAccount="bunker-certificate-sync", roleArn=role["Arn"],
                                           tags={"Application": "bunker"})
    print("Dedicated certificate synchronization role ready.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "finish", "bootstrap"])
    parser.add_argument("--certificate-arn")
    parser.add_argument("--email")
    args = parser.parse_args()
    if client("sts").get_caller_identity()["Account"] != ACCOUNT:
        raise RuntimeError("Unexpected AWS account")
    if args.action == "prepare":
        prepare()
    elif args.action == "bootstrap" and args.email:
        put_new_secret("bunker-eks-bootstrap", {"email": args.email, "password": secrets.token_urlsafe(32)})
        print("Initial administrator credential stored in bunker-eks-bootstrap.")
    elif args.action == "finish" and args.certificate_arn:
        finish(args.certificate_arn)
    else:
        parser.error("finish requires --certificate-arn; bootstrap requires --email")
