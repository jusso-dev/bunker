# ADR 0001: Stack

- Status: proposed
- Date: 2026-10-28

## Context

Bunker needs a small, reliable agent that runs on laptops, servers, CI runners and containers across Linux, macOS and Windows. It must chunk, dedupe and encrypt data locally, talk to six storage backends, and expose an MCP server. It also needs a web control plane that's easy to use and easy to self-host.

## Decision

**Agent and CLI: Rust.** One static binary per platform, low memory use, no runtime to install, and strong safety for code that touches user files. Good libraries exist for everything we need: `tokio`, `notify` for file watching, `gix` for reading git state, `rmcp` for MCP.

**Snapshot format: our own repository format modelled on restic and borg, built on proven crates.** We'll use FastCDC content-defined chunking, BLAKE3 for chunk IDs and AES-256-GCM (or XChaCha20-Poly1305) for encryption, with a per-repo data key wrapped by the org key in KMS or Key Vault. We looked at embedding `rustic_core` (a Rust port of restic). It's a strong option and we'll prototype against it first. If it fits our needs for agent-aware metadata, key wrapping and object lock, we'll use it instead of writing our own.

**Storage: Apache OpenDAL.** One Rust interface covering S3, R2, Azure Blob, Google Drive, OneDrive and local filesystems, which keeps each adapter thin.

**Control plane: TypeScript, Next.js with shadcn/ui, Postgres.** Fast to build a polished UI, and widely understood by contributors. The control plane only stores metadata, policies and events. It never holds plaintext data or unwrapped keys. Ships as a container image with a Helm chart and a Docker Compose file.

**Agent to control plane: HTTPS with mTLS** after enrolment with a one-time token. The agent works fully offline with a local policy file when no control plane is set up.

## Consequences

- Two languages (Rust and TypeScript) to maintain, which we accept for the best fit on each side.
- Shared API types are defined in OpenAPI and generated for both sides.
- Building our own repository format means more testing up front. We reduce this risk by prototyping with `rustic_core` first and fuzzing the format.
