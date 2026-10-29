# Security model and threat model

The local engine encrypts repository objects on the host, using authenticated encryption and a randomly generated data key wrapped with a passphrase-derived key. Consult the implementation and tests for the exact format at your revision. The current key hierarchy is local passphrase wrapping, not an organisation KMS or Azure Key Vault integration. There is no recovery escrow service.

## Boundaries and assumptions

The operating system, backup binary, operator and credential-injection mechanism must be trusted. Local repository permissions protect access but do not defend against an administrator, a compromised kernel, or a coding agent with the same effective privileges and environment as the operator. The control plane is designed for metadata rather than plaintext file payloads; metadata can still identify customer environments and activity.

| Threat | Current mitigation | Residual risk / required operation |
| --- | --- | --- |
| Lost storage media or remote object access | Encrypted objects and authentication tags; passphrase separate from repository | Weak/lost passphrases, endpoint compromise and availability remain operator risks. |
| Corrupt or replaced chunks/manifests | Object authentication and file-hash verification; restore verifies data | A malicious storage service can withhold/delete objects; freshness/completeness needs independent inventory. |
| Stale or wrong restore approval | Plan-bound confirmation; stale plan rejection; preview before writes | Hash-level diff needs human context; same-user CLI access is not an enforceable human/agent boundary. |
| Malicious paths/symlinks | Relative-path validation and symlink checks tested by core/discovery suites | Reparse points, hardlinks, mount races and platform-specific behavior need dedicated review. |
| Secrets in configuration | Default exclusions, structured sanitization and secret references | Heuristics do not recognize every secret. Review input and sanitized recovery; never assume universal redaction. |
| Malicious restored agent hooks/MCPs | File-only restore testing does not execute them | Review code/configuration and run readiness tests with restricted network/credentials. |
| Backup deletion by an agent | MCP does not expose deletion; cloud transport has no delete operation | Same-user filesystem write access or provider credentials can still delete data outside Bunker. Verified immutability is absent. |
| Cross-tenant control-plane access | Tenant-scoped auth/role checks and integration tests | Live deployment identity, proxy/TLS, database permissions and platform controls need verification. |
| Malicious package or build action | Checksums, source inventory and configured provenance workflow | No signed public binaries, verified notarisation or trusted update channel yet. |

Keep repository, credential files and secondary copies outside the backed-up workspace. Passphrases enter the process environment and memory; privileged processes and same-user diagnostics may observe them. Avoid tracing shells and process dumps. Secret files should be supplied by a credential manager with restrictive ownership; deleting an environment variable after use is not guaranteed memory erasure.

`rewrap-passphrase` re-wraps the same data key; it is not data-key rotation. Old headers/copies still open with old passphrases, including ciphertext encrypted with that same key after rewrapping. Replicate after rewrapping and record the new pinned recovery locator; existing encrypted chunks keep their stable namespace. Plan credential revocation and retention separately.

The production host API intentionally refuses enrolment/reporting until transport authentication is implemented. Enabling a loopback development mode is not mTLS. Do not put this configuration behind a public proxy and claim host authentication.

Security-sensitive unresolved work includes independent cryptographic/format review, fuzzing, platform race tests, hardware-backed/KMS keys, immutable storage, reliable session hooks, and full agent/MCP recovery validation. Track those as gaps in the [issue evidence](../issue-evidence.md).
