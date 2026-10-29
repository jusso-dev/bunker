# Policy reference

Local policies are TOML files passed with `--policy PATH`. Generate the installed version's defaults using `bunker policy-defaults`. Unknown fields are rejected. The standalone daemon reads local TOML; `daemon --host-config` uses the authenticated control-plane bridge and its supported policy translation.

| Local field | Default | Meaning and enforcement |
| --- | --- | --- |
| `interval_seconds` | 3600 | Snapshot interval; must be 1–31536000. |
| `jitter_seconds` | 60 | Scheduling jitter; cannot exceed the interval. |
| `size_cap_bytes` | 1073741824 | Maximum eligible bytes for one snapshot scan, not a total repository quota. |
| `max_file_bytes` | 67108864 | Maximum file size; positive and no greater than the snapshot cap. |
| `exclusions` | `[]` | Additional glob exclusions; default exclusions still apply. Invalid patterns fail validation. |
| `retention_days` | 30 | Positive retention period enforced by explicit operator-confirmed maintenance; no automatic deletion. |
| `immutable` | false | `true` is rejected for local snapshots; use explicit protected replication and its report. |
| `region` | absent | Optional label; does not enforce provider residency. |
| `dr_repository` | absent | Setting a value is rejected because protected DR policy execution is not configured. Use explicit replication only with its documented limits. |
| `restore_test_interval_seconds` | 86400 | Interval for standalone scheduled probes when `daemon --probe-config PATH` is configured. |
| `mass_delete_threshold` | 20 | Threshold used for snapshot-to-snapshot deletion alerts. |

The UI/API has a separate metadata policy contract. All fields below are required by its create/update schema; the host bridge validates its supported subset and fails closed for unsupported storage/residency modes.

| Control-plane field | Schema and purpose |
| --- | --- |
| `name` | Nonempty label, at most 100 characters. |
| `hostId` | Host UUID or null for tenant-wide intent. |
| `intervalMinutes` | Integer 5–10080. |
| `endOfSession` | Boolean event-capture policy; requires the explicitly enabled host session handler and configured native hook or wrapper. |
| `retentionDays` | Integer 1–3650; does not prove retention execution. |
| `exclusions` | Up to 100 strings, each 1–256 characters. |
| `sizeCapBytes` | Positive integer, at most 1000000000000. |
| `immutable` | Boolean protected-storage intent, not proof of object lock. |
| `drCopy` | Boolean secondary-copy intent, not proof of replication. |
| `residency` | `AU` or `unrestricted`; classification, not location enforcement. |
| `storage` | `local`, `s3`, `r2`, `azure`, `gdrive`, or `onedrive`. |
| `storageRef`, `keyRef` | Non-secret reference labels, at most 100 characters each; never credential values. |
| `massDeleteThreshold` | Integer 1–1000000. |
| `missedBackupMinutes` | Integer 10–43200. |
| `restoreTestIntervalHours` | Integer 1–8760; authenticated host probe cadence. Unconfigured probes report `not_run`. |
| `channels` | `["ui"]` or `["ui", "webhook"]`; webhook requires operator-provisioned destination and worker. |

Do not treat a saved policy as evidence of operational enforcement. Pair it with timestamped backup results, restore tests, provider settings, and an operator review.

`setup_home` opts into existing global setup capture at an explicit absolute root.
`default_includes` overrides non-secret build/cache defaults using globs; it never
overrides secret-path exclusions. Default exclusions include VCS internals, package
caches, build outputs, virtual environments, model weights and database/archive
artifacts; exclusions/skips are recorded in snapshot diagnostics. JSONC config
files are currently skipped with a sanitization diagnostic. See
[setup capture](../setup-capture.md) and [maintenance](../maintenance.md).

Configured host storage is verified before snapshot success is published, including
external recovery-report custody and policy/credential binding. See
[host storage](../host-storage.md) for supported combinations, fixed retention
horizons and retry behavior. AU residency remains fail-closed; a region label is
not a residency attestation.
