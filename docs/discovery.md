# Discovery library

`bunker-discovery` is an independent Rust library. It does not read environment
variables, inspect live configuration by default, install hooks, run agent code,
connect to MCPs, or send network requests. Callers explicitly supply paths.

## Public integration API

```rust,no_run
use bunker_discovery::{discover, DiscoveryContext, Platform, SafetyPolicy,
    prepare_files, FileFormat, sanitize};
use std::path::PathBuf;

let context = DiscoveryContext::new(
    Platform::current(), PathBuf::from("/explicit/home"),
    vec![PathBuf::from("/explicit/workspace")],
);
let policy = SafetyPolicy::default();
let results = discover(&context, &policy)?;
for result in results {
    for item in result.items {
        println!("{:?}: {}", item.category, item.path().display());
        // Group item.request() by item.root and call prepare_files ONCE per root.
        // Snapshot returned PreparedFile.bytes; do not reread item.path().
    }
}
let sanitized = sanitize(br#"{"apiKey":"example-fixture-value"}"#, FileFormat::Json)?;
assert!(!sanitized.secret_references.is_empty());
# Ok::<(), anyhow::Error>(())
```

- `DiscoveryAdapter: Send + Sync`: `id() -> AgentId`,
  `discover(&DiscoveryContext, &SafetyPolicy) -> anyhow::Result<DiscoveryResult>`,
  `session_signals() -> Vec<SessionSignal>`.
- `DiscoveryRegistry::default()` installs all five adapters. `empty`, `register`,
  `get(AgentId)`, `get_by_name(&str)`, and `discover` support composition. Names are
  `claude_code`, `cursor`, `codex`, `github_copilot`, and `kiro`. Unknown names
  return `None`; registry discovery omits agents with no matching files or exclusions.
- `DiscoveryContext { platform, home, config_dir, app_data, workspace_roots }`.
  `config_dir` is an optional explicit Linux XDG directory; `app_data` is an
  optional explicit Windows roaming directory. Container paths use Linux rules.
- `DiscoveryResult { agent, items, workspace_roots, session_signals, excluded }`.
  Each `DiscoveredItem { agent, category, root, relative_path, format, size_bytes }`
  has `request() -> FileRequest` and `path() -> PathBuf`. Discovery is metadata
  only. It does not sanitize or certify source content; prepare it before backup.
- Categories: `McpConfig`, `Skill`, `Rule`, `SubAgent`, `Hook`, `Memory`, `Settings`.
  A mixed settings/MCP file is classified `Settings` and still fully sanitized.
- `sanitize(&[u8], FileFormat) -> Result<SanitizedContent>` returns `bytes`, `modified`, and
  `secret_references`. `FileFormat::{Json,Toml,Text}` and `for_path(&Path)` are
  reusable by core. Invalid structured content is an error with no source text.
- `ExclusionPolicy::new(&SafetyPolicy)?.reason(&relative_path)` returns an
  optional `ExclusionReason`. `validate_relative_path` rejects traversal and
  Windows path syntax even on Unix.
- `prepare_file(root, &FileRequest, &SafetyPolicy)` returns `Result<Option<PreparedFile>>`;
  `None` means excluded. `prepare_files(root, &[FileRequest], &SafetyPolicy)`
  returns `PreparedSnapshot { files, excluded, source_bytes, sanitized_bytes }`.
  `PreparedFile { relative_path, bytes, source_bytes, sanitized, secret_references }` contains
  sanitized known configurations and byte-exact ordinary assets. Group requests by root, including requests from multiple
  agents, to enforce the cap over the complete repository. Core must also enforce
  its cap over workspace files and setup combined when building one snapshot.

## Paths and scope

All platforms scan explicitly supplied home and project roots. Linux editor
settings use `$XDG_CONFIG_HOME` (explicit `config_dir`) or `home/.config`; macOS
uses `home/Library/Application Support`; Windows uses explicit `app_data` or
`home/AppData/Roaming`. These are path construction rules, not environment reads.

| Agent | Home and project paths | Editor configuration |
| --- | --- | --- |
| Claude Code | `.claude/{settings.json,settings.local.json,CLAUDE.md,mcp.json,skills/,commands/,rules/,agents/,hooks/,memory/}`; home `.claude.json`, `CLAUDE.md`; project `CLAUDE.md`, `.mcp.json` | None |
| Cursor | `.cursor/{mcp.json,settings.json,hooks.json,rules/,skills/,agents/,hooks/}`; project `.cursorrules`, `AGENTS.md` | `Cursor/User/{settings.json,mcp.json}` |
| Codex | `.codex/{config.toml,AGENTS.md,AGENTS.override.md,prompts/,skills/,rules/,agents/,hooks/,memory/}`; project `AGENTS.md`, `AGENTS.override.md`, corresponding `.agents/` paths | None |
| GitHub Copilot | `.copilot/{config.json,mcp-config.json,copilot-instructions.md,skills/,agents/,hooks/}`; project `.github/{copilot-instructions.md,instructions/,prompts/,chatmodes/,agents/,skills/,hooks/}`, `.vscode/{mcp.json,settings.json}` | `Code/User/{settings.json,mcp.json}` |
| Kiro | `.kiro/{settings/mcp.json,settings/settings.json,steering/,specs/,hooks/,agents/,skills/}` | `Kiro/User/{settings.json,mcp.json}` |

Only listed files/directories are candidates. Nested safe files under listed
directories are categorized with their parent. Exclusions always apply first.
Missing files are normal; inaccessible or unsafe existing candidates are skipped
with diagnostics, without aborting other candidates or agents.

## Safety contract

Hard exclusions cover environment files, credential/key stores, VCS internals,
all JSONL, and actual private data directly under recognized agent roots (such
as sessions, projects, auth, and history). They cannot be overridden. Names such
as `chat`, `history`, `logs`, `vendor`, `out`, and `build` inside skills, commands,
rules, or ordinary source directories are valid assets and remain eligible.

Default artifact exclusions cover `target`, `.venv`, `dist`, `.next`,
`__pycache__`, `.gradle`, `.pnpm-store`, `build`, model weights, and SQLite files,
plus other common dependency/cache/output directories. Source and agent asset
folders are exempt from ambiguous directory-name defaults. `default_includes`
globs in both `SafetyPolicy` and core `Policy` can explicitly select non-secret
default artifacts; for example `default_includes = ["target/debug/tool", "**/*.sqlite"]`.
Explicit policy exclusions and hard exclusions always win. A descendant include
causes traversal of the excluded artifact directory, not inclusion of all its files.

Defaults cap individual reads at 8 MiB (known-config sanitization independently
caps input at 1 MiB) and each prepared repository at 256 MiB. Source and output
must both fit. A repository total overflow refuses the snapshot. Per-file read,
size, unsafe-path, and malformed-config failures are reported in `excluded` and
other files continue. Preparation copies ordinary binary/prose/source bytes
exactly, regardless of file extension or a caller-supplied format hint. Known
configuration suffixes at any workspace depth always receive strict sanitization.
JSONC comments and trailing commas are unsupported: affected known configs are
skipped with a clear diagnostic, never copied unparsed. Ordinary JSONC source
assets remain byte-exact.

Case-colliding files and directory aliases are skipped with diagnostics rather
than aborting the snapshot. Unicode lowercase comparison is supported; Unicode
canonical normalization (NFC/NFD) is not yet implemented. Source names are never
silently rewritten.

Reads use capability-based handles and refuse symlinks at every root and relative
path component. Callers must provide absolute roots with no symlink ancestors
(on macOS, canonicalize known fixture temp roots before use). This is deliberately
strict for mounted/aliased home directories. Relative paths must be normalized.

JSON/TOML are parsed structurally. Secret-bearing keys, all environment/header
values, unsafe command strings, literal command arguments, recognizable tokens,
any URL with userinfo or query parameters becomes a rebind reference, regardless
of parameter name. Existing explicit
`$NAME`, `${NAME}`, `${env:NAME}`, `${input:NAME}`, `env://`, `vault://`, `op://`
and `secret://` references are retained. Unknown literal credentials become
`${BUNKER_SECRET_N}` with `ReferenceKind::RebindRequired` and a field/line location.
These are placeholders only: discovery does not know an existing vault location,
store original values in a vault, or automatically resolve placeholders on
restore. The restore UI must request reauthentication/rebinding before using
such settings. Reference numbering is local to each file.

Explicit `sanitize(..., FileFormat::Text)` replaces whole sensitive lines.
The sanitizer rejects private-key material and binary content; ordinary discovery
assets bypass sanitization and remain byte-exact. Raw values are absent from parser errors and Debug output.
Structured fields named history, messages, transcripts, conversations, sessions,
or projects are omitted recursively to avoid embedded conversation caches. This
can also omit legitimate similarly named settings; restoration may need repair.

## Session signals and omissions

Signals describe capabilities, not evidence of installation or actual sessions.
Claude exposes native `SessionStart` / `SessionEnd`. Codex `notify` and Cursor
`stop` are turn-complete signals, not session-end claims. Other session-end
notifications require an external launcher/wrapper. All agents expose scheduled
fallback. Scheduler/hook installation, event authentication, deduplication,
snapshot triggering, missed-run alerts and sandbox boot/MCP probes belong to
core, not this crate. No hook commands are executed by discovery.

Version-specific Kiro/Copilot lifecycle hooks are not asserted without a verified
runtime capability probe. JetBrains version/profile-specific Copilot stores,
VS Code/Cursor profiles, remote/managed policy stores, custom `CODEX_HOME`,
custom agent directories, project roots inferred from history, and Claude
project-history memory stores are not scanned. An administrator can supply
explicit alternate roots or a custom adapter. JSONC comments/trailing commas
are rejected rather than repaired; some editor configurations therefore need
conversion to strict JSON before backup. Included org-managed plain files use
the same read-only policy; inaccessible ones report an error.

Secret detection is conservative, not a proof that arbitrary free-form documents
contain no secret or customer data. Unknown prose credentials cannot reliably be
identified. Exclude additional sensitive directories through policy; do not
represent this as a DLP engine. Literal MCP arguments are intentionally redacted
even when they look harmless, and text line redaction may require repair before
restored scripts are executable. No real user configuration is used in tests.


## Core snapshot and restore integration after review round 1

Discovery's conservative filtering applies to discovered agent setup candidates.
It must not be reused as a general workspace source filter. The core snapshotter
preserves ordinary workspace files byte-for-byte, including binaries, lockfiles,
JSONC, YAML, UUIDs, and source identifiers. Discovery also records excluded setup candidates in `DiscoveryResult.excluded`
with root, relative path, and reason. Structured sanitization is restricted
to the exact agent settings paths listed by `repository::agent_config`; each is
capped at 1 MiB before parsing. Rule prose, source code, and arbitrary JSON/TOML
are not rewritten. This is not a guarantee that ordinary source contains no
credentials. Environment/credential path exclusions still apply, and policy
can exclude additional sensitive paths.

Core `Manifest.diagnostics` records each excluded/skipped path, a reason, and
attempt count. Reads are attempted at most three times. Ordinary source folders and agent assets named `chat`, `history`, `logs`,
`profiles`, `browser`, `vendor`, or `build` remain eligible. Build/cache defaults
apply outside those source/asset scopes. Agent private
subdirectories remain filtered within recognized agent roots. An unreadable or
unsupported file is recorded as a partial capture, not silently counted as a
successful capture of that file. Size-cap overflow for the entire workspace
still refuses publication.

`SanitizedContent.modified` tracks semantic removal of history/messages/projects
as well as credential replacement. Unmodified configuration retains its original
bytes. Encrypted `FileEntry` records now persist `secret_references` and
`sanitized`; old manifests deserialize these as empty/false. Placeholders are not
resolved automatically. Local restore refuses to overwrite existing settings
with semantically sanitized content (including removal-only edits with zero
secret references) unless `--allow-rebind-overwrite` is supplied. The plan flags
these changes with `requires_rebind`. New-file
restores still require rebinding before the settings will work. Existing snapshots
cannot retroactively recover omitted reference metadata or corrupted source.
Legacy configuration placeholders are conservatively detected for the overwrite
guard even when reference metadata is absent.

`Repository::plan` provides a local redacted content preview (at most 16 KiB per
file), sizes, and executable-mode changes. Binary/large/unsupported sensitive
content has no text preview. Destination hashing is streamed; a plan is capped
at 10,000 files and 4 MiB of preview text. The MCP adapter removes `preview`, `confirmation`, and the unkeyed `before`/`after`
content hashes; it exposes only opaque identifiers and metadata, preventing a
content-hash dictionary oracle. A future
control-plane approval bridge must also keep content previews local, authenticate
its independent authority, and bind its claim to the exact local restore plan.
Local `plan`, `restore`, and `restore_with_options` remain callable for that bridge.

MCP `request_restore` records metadata only. `approve --confirm` deliberately
refuses execution pending independent human authentication. A repository
passphrase, confirmation digest, or TTY does not prove human authority. Direct
local restore remains an operator API, not an independent authorization boundary.
An agent with the same OS identity can invoke local APIs or modify files and keys;
this implementation cannot protect a filesystem from that principal. No signed
approval bridge or production integration is claimed here. Requests are capped
at 1 MiB each and 1,024 stored requests; quota exhaustion requires operator
maintenance. `Repository::prune_requests(limit)` is an operator-only bounded API
(1–1,024 entries per call) for decided and expired requests. It authenticates
records, retains active pending or corrupt requests, and audits before deleting.
It needs parent CLI registration and is deliberately unavailable through MCP.
Retention/GC is not exposed to MCP.

Restores stage encrypted target data and preimages before applying files and
persist an encrypted journal under `transactions/<id>/`. `restore-journal <id>`
shows local status, preimage indices, and any in-flight file. Failures retain this
evidence and return the transaction ID. Completed transactions retain preimages and journals but delete staged `.after`
files. Interrupted transactions retain staged data for investigation. This is crash tracking, not an all-files atomic filesystem transaction;
there is no automatic rollback/recovery command yet. Investigate interrupted
transactions before retrying. Writes sync file data and parent directories, and
new-file publication uses no-clobber creation. Snapshot chunks sync file data
individually, then sync the chunks directory once before manifest publication. Executable permission is restored;
other permissions/ACLs/ownership are not modeled.

The daemon retains its last valid policy through partial policy edits and uses
durable exponential backoff on repository/state/audit errors, growing to the
configured policy interval. A persistent failure streak produces one error audit;
no full scan runs before its retry deadline, including after restart. Malformed
schedule JSON is preserved under a unique name, audited, and replaced with safe
default state. Status uses a permission-restricted Unix socket (0600), not TCP;
the status endpoint is disabled on non-Unix platforms pending a protected
platform transport. Daemon backup scheduling still works there. It persists the successful
snapshot ID before detection/audit; pending detection retries do not repeat that
snapshot. Missing prior manifests produce a detection-gap audit event. Audit
failure remains visible and retryable rather than terminating the daemon.

`rewrap-passphrase` is the canonical command (`rotate-key` remains a compatibility
alias). It rewraps the same data key and changes the header-derived replication
namespace; it is not data-key rotation and does not revoke copies of the old
wrapped key. Export validates the exact ciphertext buffer it returns. Replication
requires backend conditional-create support. Google Drive and OneDrive are
rejected during configuration because their adapters lack this guarantee. Recovery publishes with atomic
no-clobber directory rename on supported platforms. `replicate --snapshot <id>`
and `recover --snapshot <id>` isolate an explicitly selected snapshot from other
damaged manifests; full-inventory operations fail on damage rather than claim
complete success. The recovered count is only the number of observed, verified
snapshots. Omission, rollback, or a missing latest snapshot cannot be detected
without an external trusted checkpoint, which is not implemented.

Unmet capabilities remain explicit: global discovered agent setup is not wired
into core workspace snapshots; lifecycle hooks are not installed or authenticated;
restore tests verify file recovery but do not boot an agent or probe live MCPs;
no control-plane approval bridge exists; retention/GC and scheduled restore-probe
enforcement are not implemented (`retention_days` and
`restore_test_interval_seconds` are declarations only). MCP protocol/privacy
regression tests do not establish live agent integration. No production provider,
Windows, or Linux runtime success is implied by macOS fixture tests. Issue #26
remains deferred.


### Storage credential boundary

S3/R2 now require explicit `options.bucket`, `options.region`, and an HTTPS
`options.endpoint`, plus `credential_env.access_key_id` and
`credential_env.secret_access_key`; `credential_env.session_token` is optional.
AWS environment endpoint/region overrides, profiles, SSO, workload identity,
container credentials, and IMDS are not fallback sources. Azure requires explicit
`options.container` and HTTPS `options.endpoint`, plus either
`credential_env.sas_token` or `credential_env.account_key` with explicit
`options.account_name`. The two Azure credential modes cannot be combined.
Credential environment mappings contain variable names, not literal values.
Empty or missing explicitly named credentials fail closed.

The typed OpenDAL builders replace the default provider chains with static-only
chains. Azure certificate, CLI, workload identity, environment, and IMDS providers
are not selected. A subprocess regression test supplies conflicting ambient
credentials, endpoint overrides, and fixture certificate/config/token paths,
then intercepts signed HTTP requests without contacting a cloud service. It
checks explicit S3 credentials/region/endpoint, Azure SharedKey/SAS, and refusal
when explicit configuration is missing. Direct `reqsign-*` dependencies are pinned
to the existing locked versions to construct these providers.

The parent integration feature-gates Azure certificate support and removes `rsa`
from the resolved build; `cargo tree -p bunker -i rsa --offline` reports no matching
package. Static-only credential chains remain in place. This dependency removal
is not a claim that every dependency is free of advisories. See parent-owned
`docs/dependency-security.md` for the provider feature gate and advisory review.

Scheduler and MCP expose `daemon_with_key_source`, `tick_with_key_source`,
`load_schedule_with_key_source`, and `serve_with_key_source` for explicit managed
key sources; existing passphrase entry points remain wrappers. No key source or
credential is included in daemon logs or status metadata.
