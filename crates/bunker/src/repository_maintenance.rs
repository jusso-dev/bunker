//! Explicit operator-only local retention. Opening a repository never runs GC.
use super::*;
use cap_fs_ext::DirExt;
use std::collections::BTreeSet;

const GRACE: u64 = 24 * 60 * 60;
const PLAN_TTL: u64 = 15 * 60;
const MAX_ENTRIES: usize = 200_000;
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const JOURNAL: &str = "maintenance-journal";
const JOURNAL_CONTEXT: &[u8] = b"bunker-local-maintenance-v1";

/// A short-lived, authenticated dry run. Paths contain repository object IDs only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MaintenancePlan {
    pub version: u32,
    pub as_of: u64,
    pub retention_days: u32,
    pub orphan_grace_seconds: u64,
    pub retained_snapshots: Vec<String>,
    pub snapshots: Vec<String>,
    pub chunks: Vec<String>,
    pub requests: Vec<String>,
    pub temporary_files: Vec<String>,
    pub reclaim_bytes: u64,
    /// A previous confirmed run stopped. This plan safely rolls forward.
    pub interrupted: bool,
    pub inventory_digest: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceReport {
    pub snapshots_removed: usize,
    pub chunks_removed: usize,
    pub requests_removed: usize,
    pub temporary_files_removed: usize,
    pub bytes_removed: u64,
    pub resumed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionJournal {
    version: u32,
    plan: MaintenancePlan,
}

#[derive(Serialize)]
struct Object {
    size: u64,
    modified_ns: u128,
    digest: String,
}

struct Inventory {
    dirs: BTreeMap<String, Dir>,
    objects: BTreeMap<String, Object>,
    directories: BTreeSet<String>,
    manifests: Vec<Manifest>,
    requests: Vec<(String, serde_json::Value)>,
    journals: Vec<serde_json::Value>,
    schedule_pins: BTreeSet<String>,
    interrupted: bool,
    scanned_bytes: u64,
    metadata_bytes: u64,
}

fn temporary(name: &str) -> bool {
    name.strip_prefix(".bunker-")
        .and_then(|s| s.strip_suffix(".tmp"))
        .is_some_and(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
}

fn entries(dir: &Dir, remaining: usize) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for entry in dir.entries()? {
        ensure!(
            result.len() < remaining,
            "maintenance inventory entry limit exceeded"
        );
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("non-UTF-8 repository entry"))?;
        safe_path(&name)?;
        ensure!(!name.contains('/'), "non-flat repository entry");
        result.push(name);
    }
    result.sort();
    Ok(result)
}

impl Inventory {
    fn record(&mut self, dir: &Dir, name: &str, path: &str, maximum: u64) -> Result<()> {
        ensure!(
            self.objects.len() < MAX_ENTRIES,
            "maintenance inventory entry limit exceeded"
        );
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let mut file = dir.open_with(name, &options)?;
        let before = file.metadata()?;
        ensure!(
            before.is_file() && before.len() <= maximum,
            "invalid maintenance object: {path}"
        );
        self.scanned_bytes = self
            .scanned_bytes
            .checked_add(before.len())
            .context("inventory size overflow")?;
        ensure!(
            self.scanned_bytes <= MAX_SCAN_BYTES,
            "maintenance scan exceeds 64 GiB safety limit"
        );
        let mut hash = blake3::Hasher::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut read = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            read += n as u64;
            ensure!(
                read <= before.len(),
                "maintenance object grew while reading"
            );
            hash.update(&buffer[..n]);
        }
        let after = file.metadata()?;
        ensure!(
            read == before.len()
                && before.len() == after.len()
                && before.modified()? == after.modified()?,
            "maintenance object changed while reading"
        );
        self.objects.insert(
            path.into(),
            Object {
                size: read,
                modified_ns: after
                    .modified()?
                    .into_std()
                    .duration_since(UNIX_EPOCH)?
                    .as_nanos(),
                digest: hash.finalize().to_hex().to_string(),
            },
        );
        Ok(())
    }

    fn metadata(&mut self, dir: &Dir, name: &str, path: &str, maximum: u64) -> Result<Vec<u8>> {
        let bytes = read_bounded(dir, name, maximum)?;
        self.metadata_bytes += bytes.len() as u64;
        ensure!(
            self.metadata_bytes <= MAX_MANIFEST,
            "maintenance metadata exceeds 64 MiB safety limit"
        );
        ensure!(
            self.objects[path].digest == blake3::hash(&bytes).to_hex().as_str(),
            "maintenance metadata changed while reading"
        );
        Ok(bytes)
    }
}

impl Repository {
    /// Authenticate published objects and fingerprint the bounded local inventory without mutation.
    /// Remote replicas, checkpoints and restore preimages are never deletion targets.
    pub fn maintenance_plan(&self, policy: &Policy) -> Result<MaintenancePlan> {
        policy.validate()?;
        self.maintenance_plan_at(policy.retention_days, now())
            .map(|(plan, _)| plan)
    }

    fn maintenance_inventory(&self) -> Result<Inventory> {
        let mut inv = Inventory {
            dirs: BTreeMap::new(),
            objects: BTreeMap::new(),
            directories: BTreeSet::new(),
            manifests: vec![],
            requests: vec![],
            journals: vec![],
            schedule_pins: BTreeSet::new(),
            interrupted: false,
            scanned_bytes: 0,
            metadata_bytes: 0,
        };
        // Header validation also detects a rewrap since this handle was unlocked.
        self.encrypted_object("repository.json")?;
        inv.record(&self.dir, "repository.json", "repository.json", 8192)?;
        match self.dir.symlink_metadata("schedule.json") {
            Ok(_) => {
                inv.record(&self.dir, "schedule.json", "schedule.json", 1024 * 1024)?;
                let bytes =
                    inv.metadata(&self.dir, "schedule.json", "schedule.json", 1024 * 1024)?;
                let state: crate::scheduler::ScheduleState = serde_json::from_slice(&bytes)
                    .context("invalid scheduler state; maintenance refused")?;
                let mut pins = vec![state.last_snapshot];
                if let Some((before, after)) = state.pending_detection {
                    pins.extend([before, Some(after)]);
                }
                if let Some(setup) = state.pending_setup {
                    pins.push(Some(setup.workspace_snapshot));
                }
                for id in pins.into_iter().flatten() {
                    valid_id(&id)?;
                    inv.schedule_pins.insert(id);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        match self.dir.open_dir_nofollow("host") {
            Ok(host) => {
                inv.directories.insert("host".into());
                match host.symlink_metadata("schedule") {
                    Ok(_) => {
                        inv.record(&host, "schedule", "host/schedule", 1024 * 1024)?;
                        let bytes =
                            inv.metadata(&host, "schedule", "host/schedule", 1024 * 1024)?;
                        let plain = self.open_metadata(b"bunker-host-schedule-v1", &bytes)?;
                        inv.schedule_pins
                            .extend(crate::host_runtime::maintenance_pins(&plain)?);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        for category in ["snapshots", "chunks", "requests"] {
            let dir = self.dir.open_dir_nofollow(category)?;
            for name in entries(&dir, MAX_ENTRIES - inv.objects.len())? {
                let path = format!("{category}/{name}");
                let is_temp = temporary(&name);
                if !is_temp {
                    valid_id(&name).context("ambiguous maintenance inventory")?;
                }
                let max = match category {
                    "chunks" => 8 * 1024 * 1024 + 40,
                    "requests" => 1024 * 1024 + 40,
                    _ => MAX_MANIFEST,
                };
                inv.record(&dir, &name, &path, max)?;
                if is_temp {
                    continue;
                }
                match category {
                    "snapshots" => {
                        ensure!(
                            inv.manifests.len() < 10_000,
                            "snapshot inventory limit exceeded"
                        );
                        let bytes = inv.metadata(&dir, &name, &path, MAX_MANIFEST)?;
                        inv.manifests.push(self.decode_manifest(&name, &bytes)?);
                    }
                    "requests" => {
                        ensure!(
                            inv.requests.len() < 1024,
                            "request inventory limit exceeded"
                        );
                        let bytes = inv.metadata(&dir, &name, &path, max)?;
                        let value = serde_json::from_slice(&crypto::open(
                            &self.key,
                            &bytes,
                            name.as_bytes(),
                        )?)?;
                        inv.requests.push((name, value));
                    }
                    _ => {
                        let bytes = read_bounded(&dir, &name, max)?;
                        ensure!(
                            inv.objects[&path].digest == blake3::hash(&bytes).to_hex().as_str(),
                            "chunk changed during inventory"
                        );
                        self.decode_chunk(&name, &bytes)?;
                    }
                }
            }
            inv.directories.insert(category.into());
            inv.dirs.insert(category.into(), dir);
        }
        let transactions = match self.dir.open_dir_nofollow("transactions") {
            Ok(dir) => Some(dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if let Some(transactions) = transactions {
            inv.directories.insert("transactions".into());
            for id in entries(&transactions, MAX_ENTRIES - inv.objects.len())? {
                valid_id(&id)?;
                let dir = transactions.open_dir_nofollow(&id)?;
                inv.directories.insert(format!("transactions/{id}"));
                let names = entries(&dir, MAX_ENTRIES - inv.objects.len())?;
                // Missing/partial journals are ambiguous: keep everything, refuse deletion.
                ensure!(
                    names.iter().any(|n| n == "journal"),
                    "transaction {id} has no authenticated journal"
                );
                for name in names {
                    let known = name == "journal"
                        || name == "git-journal"
                        || temporary(&name)
                        || name
                            .strip_suffix(".before")
                            .or_else(|| name.strip_suffix(".after"))
                            .is_some_and(|n| {
                                !n.is_empty()
                                    && n.len() <= 10
                                    && n.bytes().all(|b| b.is_ascii_digit())
                            });
                    ensure!(known, "unknown transaction object");
                    let path = format!("transactions/{id}/{name}");
                    inv.record(&dir, &name, &path, 1024 * 1024 * 1024 + 40)?;
                    if name == "journal" || name == "git-journal" {
                        let bytes = inv.metadata(&dir, &name, &path, MAX_MANIFEST + 40)?;
                        let plain = crypto::open(&self.key, &bytes, id.as_bytes())?;
                        if name == "journal" {
                            let value: serde_json::Value = serde_json::from_slice(&plain)?;
                            ensure!(value["id"] == id, "restore journal identity mismatch");
                            inv.journals.push(value);
                        } else {
                            let _: bunker_git::Journal = serde_json::from_slice(&plain)?;
                        }
                    }
                }
            }
        }
        match self.dir.symlink_metadata(JOURNAL) {
            Ok(_) => {
                inv.record(&self.dir, JOURNAL, JOURNAL, MAX_MANIFEST)?;
                let bytes = inv.metadata(&self.dir, JOURNAL, JOURNAL, MAX_MANIFEST)?;
                let journal: DeletionJournal =
                    serde_json::from_slice(&crypto::open(&self.key, &bytes, JOURNAL_CONTEXT)?)?;
                ensure!(
                    journal.version == 1 && journal.plan.version == 1,
                    "unsupported maintenance journal"
                );
                ensure!(
                    journal.plan.confirmation == self.maintenance_confirmation(&journal.plan)?,
                    "invalid maintenance journal plan"
                );
                inv.interrupted = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // Do not follow a symlink when publishing the completion audit record either.
        match self.dir.open_dir_nofollow("audit") {
            Ok(_) => {
                inv.directories.insert("audit".into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        inv.manifests
            .sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(inv)
    }

    fn maintenance_plan_at(
        &self,
        retention_days: u32,
        as_of: u64,
    ) -> Result<(MaintenancePlan, Inventory)> {
        ensure!(retention_days > 0, "retention_days must be positive");
        let inv = self.maintenance_inventory()?;
        let cutoff = as_of.saturating_sub(u64::from(retention_days) * 86400);
        let mut protected = inv.schedule_pins.clone();
        let mut requests = vec![];
        for (id, request) in &inv.requests {
            if let Some(frozen) = request
                .get("frozen")
                .or_else(|| request.get("bridge_intent"))
            {
                // Remote status is not local authority to discard a frozen approval.
                protect_snapshot(&frozen["plan"], &mut protected)?;
                continue;
            }
            let status = request["status"]
                .as_str()
                .context("unknown request schema; maintenance refused")?;
            ensure!(
                matches!(status, "pending" | "approved" | "denied" | "expired"),
                "unknown request status"
            );
            let expiry = request["expires_at"]
                .as_u64()
                .context("invalid request expiry")?;
            if status == "pending" && expiry > as_of {
                protect_snapshot(&request["plan"], &mut protected)?;
            } else {
                requests.push(id.clone());
            }
        }
        for journal in &inv.journals {
            let status = journal["status"]
                .as_str()
                .context("invalid restore journal status")?;
            match status {
                // Even terminal journals can be used for explicit rollback. Keep their
                // snapshot until a separate transaction archival policy exists.
                "completed"
                | "completed_audit_failed"
                | "rolled_back"
                | "staging"
                | "applying"
                | "interrupted"
                | "recovering" => protect_snapshot(&journal["plan"], &mut protected)?,
                _ => bail!("unknown restore journal status; maintenance refused"),
            }
        }
        let manifest_ids: BTreeSet<_> = inv.manifests.iter().map(|m| m.id.clone()).collect();
        ensure!(
            protected.is_subset(&manifest_ids),
            "protected snapshot is missing; maintenance refused"
        );
        // Keep a recovery point for each authenticated agent/session scope. Setup
        // groups are indivisible: retaining one root must retain its siblings.
        let mut latest_workspace = BTreeMap::new();
        let mut latest_setup = BTreeMap::new();
        let mut setup_groups: BTreeMap<&str, Vec<&Manifest>> = BTreeMap::new();
        for manifest in &inv.manifests {
            if let Some(scope) = &manifest.setup {
                setup_groups
                    .entry(&scope.capture_id)
                    .or_default()
                    .push(manifest);
            } else {
                latest_workspace.insert((&manifest.agent, &manifest.session), &manifest.id);
            }
            if manifest.created_at >= cutoff {
                protected.insert(manifest.id.clone());
            }
        }
        protected.extend(latest_workspace.values().map(|id| (*id).clone()));
        for members in setup_groups.values() {
            let first = members[0].setup.as_ref().unwrap();
            let mut indices = BTreeSet::new();
            for manifest in members {
                let scope = manifest.setup.as_ref().unwrap();
                ensure!(
                    scope.scope_count == first.scope_count
                        && scope.session_event == first.session_event
                        && indices.insert(scope.scope_index),
                    "inconsistent setup capture group; maintenance refused"
                );
            }
            // An interrupted publication is evidence, not a complete replacement
            // for the preceding capture. Preserve it for explicit future cleanup.
            if members.len() != first.scope_count as usize {
                protected.extend(members.iter().map(|m| m.id.clone()));
            } else {
                for manifest in members {
                    let scope = manifest.setup.as_ref().unwrap();
                    let mut agents = scope.agents.clone();
                    agents.sort();
                    let value = (manifest.created_at, &manifest.id);
                    let latest = latest_setup
                        .entry((scope.source_root.clone(), agents))
                        .or_insert(value);
                    *latest = (*latest).max(value);
                }
            }
        }
        protected.extend(latest_setup.values().map(|(_, id)| (*id).clone()));
        for members in setup_groups.values() {
            if members.iter().any(|m| protected.contains(&m.id)) {
                protected.extend(members.iter().map(|m| m.id.clone()));
            }
        }
        let mut retained = vec![];
        let mut snapshots = vec![];
        let mut reachable = BTreeSet::new();
        let mut all_referenced = BTreeSet::new();
        // All manifests were authenticated before computing any reachability.
        for manifest in &inv.manifests {
            ensure!(
                manifest.created_at <= as_of,
                "snapshot timestamp is in the future; maintenance refused"
            );
            let chunks = self.snapshot_chunks(manifest)?;
            for chunk in &chunks {
                ensure!(
                    inv.objects.contains_key(&format!("chunks/{chunk}")),
                    "manifest references missing chunk; maintenance refused"
                );
                all_referenced.insert(chunk.clone());
            }
            if manifest.created_at >= cutoff || protected.contains(&manifest.id) {
                retained.push(manifest.id.clone());
                reachable.extend(chunks);
            } else {
                snapshots.push(manifest.id.clone());
            }
        }
        let mut chunks = vec![];
        let mut temporary_files = vec![];
        for (path, object) in &inv.objects {
            let (category, name) = match path.split_once('/') {
                Some(parts) => parts,
                None => continue,
            };
            let aged =
                object.modified_ns <= u128::from(as_of.saturating_sub(GRACE)) * 1_000_000_000;
            if matches!(category, "snapshots" | "chunks" | "requests") && temporary(name) {
                if aged {
                    temporary_files.push(path.clone());
                }
            } else if category == "chunks"
                && !reachable.contains(name)
                && (all_referenced.contains(name) || aged)
            {
                chunks.push(name.to_string());
            }
        }
        snapshots.sort();
        retained.sort();
        let reclaim_bytes = snapshots
            .iter()
            .map(|id| format!("snapshots/{id}"))
            .chain(chunks.iter().map(|id| format!("chunks/{id}")))
            .chain(requests.iter().map(|id| format!("requests/{id}")))
            .chain(temporary_files.iter().cloned())
            .map(|path| inv.objects[&path].size)
            .sum();
        let mut plan = MaintenancePlan {
            version: 1,
            as_of,
            retention_days,
            orphan_grace_seconds: GRACE,
            retained_snapshots: retained,
            snapshots,
            chunks,
            requests,
            temporary_files,
            reclaim_bytes,
            interrupted: inv.interrupted,
            inventory_digest: blake3::hash(&serde_json::to_vec(&(&inv.directories, &inv.objects))?)
                .to_hex()
                .to_string(),
            confirmation: String::new(),
        };
        plan.confirmation = self.maintenance_confirmation(&plan)?;
        Ok((plan, inv))
    }

    fn maintenance_confirmation(&self, plan: &MaintenancePlan) -> Result<String> {
        let mut unsigned = plan.clone();
        unsigned.confirmation.clear();
        let mut hash = blake3::Hasher::new_keyed(&self.key);
        hash.update(JOURNAL_CONTEXT);
        hash.update(&serde_json::to_vec(&unsigned)?);
        Ok(hash.finalize().to_hex().to_string())
    }

    /// Explicit human/operator confirmation only. Never expose via MCP or agent tools.
    /// Uses the Repository's exclusive lock; callers must serialize use of this handle.
    pub fn maintenance_execute(
        &self,
        plan: &MaintenancePlan,
        confirmation: &str,
    ) -> Result<MaintenanceReport> {
        let current = now();
        ensure!(
            current >= plan.as_of && current - plan.as_of <= PLAN_TTL,
            "maintenance plan expired; obtain a new dry run"
        );
        ensure!(
            confirmation == plan.confirmation
                && confirmation == self.maintenance_confirmation(plan)?,
            "maintenance confirmation mismatch"
        );
        let (fresh, inv) = self.maintenance_plan_at(plan.retention_days, plan.as_of)?;
        ensure!(
            &fresh == plan,
            "maintenance inventory changed; obtain a new dry run"
        );
        match self.dir.create_dir("audit") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let audit = self.dir.open_dir_nofollow("audit")?;
        let journal = DeletionJournal {
            version: 1,
            plan: plan.clone(),
        };
        let bytes = serde_json::to_vec(&journal)?;
        ensure!(
            bytes.len() as u64 + 40 <= MAX_MANIFEST,
            "maintenance journal exceeds safety limit"
        );
        atomic_write(
            &self.dir,
            JOURNAL,
            &crypto::seal(&self.key, &bytes, JOURNAL_CONTEXT)?,
            true,
        )?;
        // A durable authorization record precedes every unlink. Manifest fsync precedes
        // chunk unlinks: a crash can leave orphans, never retained dangling references.
        for (category, ids) in [
            ("snapshots", &plan.snapshots),
            ("requests", &plan.requests),
            ("chunks", &plan.chunks),
        ] {
            let dir = &inv.dirs[category];
            for id in ids {
                dir.remove_file(id)?;
            }
            dir.try_clone()?.into_std_file().sync_all()?;
        }
        for path in &plan.temporary_files {
            let (category, name) = path.split_once('/').context("invalid temporary path")?;
            inv.dirs[category].remove_file(name)?;
        }
        for dir in inv.dirs.values() {
            dir.try_clone()?.into_std_file().sync_all()?;
        }
        // Keep a normal encrypted audit record. Failure retains the deletion journal,
        // making incomplete finalization visible to the next operator dry run.
        let audit_id = hex::encode(crypto::random::<32>());
        let audit_bytes = serde_json::to_vec(&serde_json::json!({
            "at": now(), "event": "local_maintenance_completed", "detail": {"plan": plan}
        }))?;
        atomic_write(
            &audit,
            &audit_id,
            &crypto::seal(&self.key, &audit_bytes, audit_id.as_bytes())?,
            false,
        )?;
        self.dir.remove_file(JOURNAL)?;
        self.dir.try_clone()?.into_std_file().sync_all()?;
        Ok(MaintenanceReport {
            snapshots_removed: plan.snapshots.len(),
            chunks_removed: plan.chunks.len(),
            requests_removed: plan.requests.len(),
            temporary_files_removed: plan.temporary_files.len(),
            bytes_removed: plan.reclaim_bytes,
            resumed: plan.interrupted,
        })
    }
}

fn protect_snapshot(plan: &serde_json::Value, protected: &mut BTreeSet<String>) -> Result<()> {
    let id = plan["snapshot"]
        .as_str()
        .context("invalid protected restore plan")?;
    valid_id(id)?;
    protected.insert(id.into());
    Ok(())
}
