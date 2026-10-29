# Bunker development guide

Bunker is an early implementation of encrypted backup and reviewed restore for coding-agent workspaces. Build from source and test against disposable data before adopting it. The [evidence matrix](../issue-evidence.md) records what has been checked and what remains unverified; these docs do not declare v1 complete.

Start with the [local quick start](quickstart.md), then follow the [restore runbook](restore.md). Read the [security model](security.md) before backing up an agent's configuration. The current CLI's `--help` is authoritative when developing against a different revision.

Local snapshots, encrypted object replication, and control-plane metadata are separate paths. A UI policy is not proof that the daemon received or enforced it. Provider configuration is not proof of object lock, Australian residency, KMS integration, or recoverability. See [storage](storage.md) and [compliance](../compliance/index.md).

The docs site builds with `python -m pip install -r packaging/docs-requirements.txt` followed by `mkdocs build --strict --config-file docs/user/mkdocs.yml --site-dir /tmp/bunker-docs`. CI uploads the generated site as an artifact; no public documentation deployment is configured.
