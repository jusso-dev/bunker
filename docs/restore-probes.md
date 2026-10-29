# Trusted scheduled restore-probe foundation

`restore_probes` implements a bounded restore/probe attempt. Both the standalone
daemon and authenticated host runtime schedule it using the effective restore-test
interval. Real native-agent acceptance remains open; #26 remains deferred.

Use `restore-test SNAPSHOT --workspace SOURCE --probe-config PATH` for an explicit attempt, or
`daemon --workspace PATH --probe-config PATH` for standalone scheduling. The host
runtime reads `probe_config` from its operator configuration. Configuration and
Docker runtime paths must be outside the captured workspace and repository.
For manual probes the operator must supply the original source workspace boundary;
legacy ordinary manifests do not record that origin. Setup manifests additionally
exclude their authenticated source root. These checks run before Docker execution.
The standalone daemon records encrypted evidence before advancing its next probe
time. Configuration/runtime errors use separate bounded retries and a constant
status message; they do not change the workspace backup cadence. Executed failures
are recorded as failed evidence and follow the normal test interval.

The host persists evidence IDs and bodies in its bounded encrypted outbox before
delivery, reports snapshots before evidence, and retries the exact evidence after
restart. An unconfigured host emits `not_run` with a fixed reason. Standalone
automatic probes require `--probe-config`; omitting it does not claim a boot test.

## Scheduler handoff

```rust,ignore
use bunker::restore_probes::{TrustedProbeConfig, DockerExecutor, run_restore_probes};
let config = TrustedProbeConfig::load(operator_config_path)?;
let mut executor = DockerExecutor::new(&config)?;
let evidence = run_restore_probes(&repo, &snapshot.id, &config, &mut executor)?;
results.evidence.push(evidence); // host_service::WorkResults
```

`ProbeExecutor` has `prepare(root)`,
`execute(ProbeRequest)`, and `cleanup()` methods for deterministic offline tests.
`run_restore_probes` returns `Result<host_service::RestoreEvidence>`; malformed
operator configuration is an error, whereas restore failure, dependency absence,
and executed probe results become explicit evidence. Scheduling must report the
snapshot before its evidence and must not convert a configuration/runtime error
into successful evidence. A disabled/unconfigured schedule must not invent a
successful test. Supply explicitly skipped evidence if the scheduler reports it.

`AgentProbe` and `McpProbe` retain their existing fields. `ProbeOutcome` retains
`Passed`, `Failed`, `NotRun` and adds `FailedWithReason(ProbeFailure)` and
`NotRunWithReason(ProbeSkip)`. Use `status()`, `reason()`, and `is_not_run()` rather
than equality with `NotRun` when interpreting reason-bearing results. Legacy
`Failed` and `NotRun` map to `process_failed` and `not_configured` respectively.
`RestoreEvidence` and all nested types derive lossless serde serialization for
the parent durable outbox: persist the entire value, retaining its UUID and
reason-bearing enum variants on retry. Internal durable JSON is distinct from
the API wire format; `host_service` maps it to the strict remote variants.

## Provisioned trust boundary

The operator supplies a JSON file **outside the captured workspace/repository**.
It must be a regular file, owned by the service user or root, without symlinks or
group/world-writable components (root-owned sticky ancestors are permitted).
The loader caps it at 64 KiB and rejects unknown fields. Provision the containing
directory as mode 0700 and the file as 0600. `DockerExecutor::new` also checks the
explicit Docker configuration directory and resolved CLI binary's ownership.
Platforms without the implemented Unix ownership checks fail closed.

The service account and operator are trusted: root/service-user code can change
its own configuration. An attacker able to modify the service account's files
is outside this isolation boundary. Configuration must not be sourced from a
manifest, remote policy, captured agent config, environment auto-discovery, or
untrusted project paths. The parent must select the protected provisioning path.

Example shape (replace the placeholder digest with the operator-verified digest;
pre-pull the image using the **explicit** context before enabling probes):

```json
{
  "docker_executable": "/opt/bunker/bin/docker",
  "docker_context": "homelab",
  "docker_config": "/etc/bunker/probe-docker",
  "image": "registry.example.test/bunker-probes@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "timeout_seconds": 10,
  "output_limit_bytes": 16384,
  "agents": [{
    "agent": "codex",
    "command": {
      "executable": "/opt/probes/boot-codex",
      "args": ["--inert-restore-check"],
      "requires_network": false,
      "requires_credentials": false
    }
  }],
  "mcps": [{
    "name": "local-tools",
    "command": {
      "executable": "/opt/probes/stdio-tools",
      "args": [],
      "requires_network": false,
      "requires_credentials": false
    }
  }]
}
```

These are trusted image executables with literal argument vectors. Bunker does
not evaluate shell strings or discover/execute MCP commands, hooks, extensions,
plugins or scripts from captured configuration. A real-agent wrapper must offer
an inert boot path with those mechanisms disabled; if the native agent cannot
provide one, do not provision it as a trusted restore probe. An operator-authored
wrapper is trusted code, including any interpreter arguments the operator sets.
Image contents must not contain embedded credentials. Never substitute an exit-0
wrapper for actual boot validation.

Docker transport configuration is explicit and host-side only. The Docker CLI
runs with a cleared environment and only fixed PATH, disposable HOME and the
configured DOCKER_CONFIG. SSH Docker contexts may use host SSH transport
configuration/identity under the service account; that is an operator-controlled
runtime dependency, never an agent credential mount or forwarded agent socket.
Use a dedicated service identity/context. No environment variables or credentials
are passed through into agent/MCP containers.

## Restore and isolation

The runner authenticates the manifest and file bytes before starting probes,
then materializes files into a fresh private temporary directory. Paths use the
repository's traversal validation; files are created once, mode 0444, and
executable bits are not restored. It never launches captured files. Git snapshots
are eligible: `repo.verify` authenticates their Git artifacts too,
but only verified working-file contents are restored. Git refs, index, hooks,
configuration and native worktree readiness are not restored/validated. Evidence
uses `EvidenceSandbox::ContainerFileContent`, serialized remotely as
`sandbox: "container", scope: "file-content"`; the UI explicitly states this
limited scope. Existing `Container`/`TempDirectory` evidence retains unknown
scope. No fields were added to the Rust `RestoreEvidence` struct.

Setup snapshots report `unsupported_snapshot` until native HOME layout is
implemented. Legacy file manifests containing `.git` paths also remain
unsupported rather than accidentally replaying Git configuration. Sanitization that only removed history is eligible. Existing or
rebind-required secret references and legacy `BUNKER_SECRET_` placeholders report
`credentials_unavailable`; there is no secret rebind or ambient credential
discovery. The `sanitized` flag alone is not treated as a credential dependency.

A task-owned, uniquely named Docker volume transports those files, including to
a remote context. A stopped staging container receives `docker cp`; no staging
command runs. Each probe gets a separate container with:

- the same pinned image, `--pull=never`, disabled Docker logs, and an overridden trusted entrypoint;
- a read-only root and read-only `/restore` volume with image-content copying disabled, no host bind mounts;
- UID/GID 65532, all capabilities dropped, `no-new-privileges`;
- `--network=none`, no ports, devices, Docker socket, repository or credential mounts;
- 256 MiB memory/swap ceiling, one CPU, 64 PIDs and 128 file descriptors;
- a 16 MiB noexec/nosuid/nodev `/tmp`, disposable HOME and a fixed `/restore` cwd.

Docker daemon access is inherently privileged; the daemon and configured image
are trusted infrastructure. Image-declared volumes must be reviewed by the
operator; cleanup removes anonymous volumes as well as the task-owned data
volume. This is process/container isolation, not independent remote attestation.

Limits: at most 1,000 files / 64 MiB restored bytes, 1–5 unique agents and at most
16 combined probes, 32 arguments / 8 KiB total argument bytes per command,
1–30 seconds per probe, and 256–65,536 combined stdout/stderr bytes. Docker
administrative subprocesses each have a 10-second deadline. Attempts execute
serially with a bounded number of Docker calls. Output remains local/in-memory
and is never serialized as evidence. Timeout/output overflow kills and reaps the
CLI process group; task-owned containers are forcibly removed and volumes
removed on success/failure, with a drop-time retry. Cleanup failure is failed
evidence, never success. Daemon outage can prevent remote deletion: operators
must reconcile leaked `bunker-probe-<UUID>` resources; no global prune is used.

## What a pass means

The agent wrapper must boot the intended application against `/restore` with
unsafe captured hooks disabled, verify its boot condition, and emit exactly one
JSON object to stdout before exiting successfully:

```json
{"bunkerRestoreProbe":1,"booted":true,"snapshot":"<BUNKER_SNAPSHOT_ID>"}
```

`BUNKER_RESTORE_ROOT=/restore` and the authenticated snapshot ID are supplied by
the runner. Empty output, wrong snapshot, malformed JSON and nonzero exits fail.
The response is an operator-wrapper assertion; a fake fixture proves the runner,
not real Codex/Cursor/etc. acceptance.

For MCP, Bunker sends a newline-delimited JSON-RPC `initialize` request with ID
`bunker-restore-probe`, protocol version `2024-11-05`, capabilities and clientInfo.
A pass requires matching JSON-RPC 2.0 response ID, the supported protocol version,
a capabilities object, nonempty bounded serverInfo name/version, no error, and a
successful write of `notifications/initialized` to the live stdio session. The
container is then intentionally stopped. Exit 0, arbitrary stdout, unsupported
protocol, a wrong ID or an error do not establish connectivity. This does not
validate every MCP tool, HTTP/SSE transport, arbitrary network endpoints, or
future protocol versions.

Networking/credentials are unavailable in this foundation. Commands declaring
either dependency report `not_run` with `network_unavailable` or
`credentials_unavailable`; the runner never enables networking or supplies a
credential to satisfy them. Operators must declare these prerequisites honestly.

## Remote protocol and UI

New host writers send one of these strict variants per agent/MCP:

- `{ "outcome": "passed" }`
- `{ "outcome": "failed", "reasonCode": "timeout" }`
- `{ "outcome": "not_run", "reasonCode": "credentials_unavailable" }`

Identity fields (`agent` or `name`) remain mandatory. The API still reads/writes
legacy `{ "passed": true|false }` evidence and old stored rows, without a database
migration. Upgrade the server before the new host writer: an old boolean-only
server cannot ingest the new protocol. Do not downgrade `not_run` to a boolean.
Mixed/contradictory boolean+outcome fields, reasons on success, missing reasons,
unknown reasons, and reasons in the wrong outcome category are rejected.

Failure reasons: `restore_failed`, `timeout`, `output_limit`, `process_failed`,
`invalid_boot_response`, `invalid_mcp_handshake`, `cleanup_failed`.
Skip reasons: `not_configured`, `runtime_unavailable`, `network_unavailable`,
`credentials_unavailable`, `unsupported_snapshot`, `resource_limit`.

The bridge publishes mixed reports rather than dropping reports containing a
skipped check. UI displays “skipped (not run)” and the bounded reason separately.
Only reports with every check passed contribute to the displayed fully-passed
percentage; skipped reports remain in the denominator. `restore-test-failed`
alerts and existing notification enqueueing occur only for an actual failed
probe (including legacy `passed:false`), never for a skipped probe. Identical
same-host/body evidence retries return the original acknowledgement
without repeating audit, alert creation or notification enqueueing; UUID reuse
with changed content/ownership is rejected. No unrelated notification-worker
or delivery behavior is changed. Generated OpenAPI/types
capture the strict disjoint wire variants.

## Acceptance and remaining work

Offline tests inject executors, verify authenticated disposable restore, reject
corruption, exercise skipped dependencies and cleanup failure, validate boot/MCP
responses, enforce configuration protection, and exercise real bounded local
subprocess timeout/output behavior. Control-plane tests cover schema rejection,
legacy reads, tri-state roundtrips/alerts and skipped UI rendering.

The opt-in `disposable_container_smoke` test accepts only a protected fixture
configuration through `BUNKER_PROBE_SMOKE_CONFIG` and insists on the `homelab`
Docker context. Use only fake-agent/MCP commands in a disposable pinned image;
no real agents, user configuration, cloud endpoints or notification recipients.

Remaining acceptance is real native-agent inert boot wrappers, real operator MCP
compatibility, credential/network-dependent probes, full Git/setup restoration,
non-Unix protected provisioning, production scheduled cadence/restart/retry
integration, and live deployed UI/remote-host end-to-end evidence. A successful
fake-container test does not close these gaps. #26 remains deferred.
