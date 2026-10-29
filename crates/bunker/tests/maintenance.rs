//! All destructive operations in this suite are confined to disposable TempDirs.
use bunker::{
    crypto,
    policy::Policy,
    repository::{now, Manifest, Repository},
};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "maintenance-disposable-fixture-only";
struct Fixture {
    _temp: tempfile::TempDir,
    repo: Repository,
    work: PathBuf,
    key: Zeroizing<[u8; 32]>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let repo = Repository::init(&temp.path().join("repo"), PASSPHRASE).unwrap();
        let work = temp.path().join("work");
        fs::create_dir(&work).unwrap();
        let header: Value =
            serde_json::from_slice(&fs::read(repo.root().join("repository.json")).unwrap())
                .unwrap();
        let salt: [u8; 16] = serde_json::from_value(header["salt"].clone()).unwrap();
        let wrapped: Vec<u8> = serde_json::from_value(header["wrapped_key"].clone()).unwrap();
        let wrapping = crypto::derive(PASSPHRASE, &salt).unwrap();
        let plain = crypto::open(&wrapping, &wrapped, b"bunker-repository-key-v1").unwrap();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&plain);
        Self {
            _temp: temp,
            repo,
            work,
            key,
        }
    }
    fn snapshot(&self, content: &str, days_old: u64) -> Manifest {
        fs::write(self.work.join("file"), content).unwrap();
        fs::write(self.work.join("shared"), "shared across every snapshot").unwrap();
        let mut manifest = self
            .repo
            .snapshot(&self.work, &Policy::default(), None, None, "manual")
            .unwrap();
        manifest.created_at = now() - days_old * 86400;
        self.manifest(&manifest);
        manifest
    }
    fn manifest(&self, manifest: &Manifest) {
        self.encrypted(
            &format!("snapshots/{}", manifest.id),
            &serde_json::to_value(manifest).unwrap(),
            manifest.id.as_bytes(),
        );
    }
    fn encrypted(&self, path: &str, value: &Value, aad: &[u8]) {
        let path = self.repo.root().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            crypto::seal(&self.key, &serde_json::to_vec(value).unwrap(), aad).unwrap(),
        )
        .unwrap();
    }
    fn orphan(&self, content: &[u8], age: u64) -> String {
        let id = blake3::keyed_hash(&self.key, content).to_hex().to_string();
        let path = self.repo.root().join("chunks").join(&id);
        fs::write(
            &path,
            crypto::seal(&self.key, content, id.as_bytes()).unwrap(),
        )
        .unwrap();
        aged(&path, age);
        id
    }
    fn execute(&self) -> bunker::repository::MaintenanceReport {
        let plan = self.repo.maintenance_plan(&Policy::default()).unwrap();
        self.repo
            .maintenance_execute(&plan, &plan.confirmation)
            .unwrap()
    }
}
fn aged(path: &Path, seconds: u64) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(seconds)),
        )
        .unwrap();
}
fn exists(repo: &Repository, category: &str, id: &str) -> bool {
    repo.root().join(category).join(id).exists()
}
fn file_chunk(manifest: &Manifest) -> String {
    manifest
        .files
        .iter()
        .find(|f| f.path == "file")
        .unwrap()
        .chunks[0]
        .clone()
}

#[test]
fn retention_preserves_shared_chunks_and_newest_and_restores_retained_data() {
    let f = Fixture::new();
    let old = f.snapshot("old unique", 50);
    let retained = f.snapshot("retained unique", 20);
    let newest = f.snapshot("newest unique", 0);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert_eq!(plan.snapshots, std::slice::from_ref(&old.id));
    assert_eq!(plan.chunks, [file_chunk(&old)]);
    assert!(
        exists(&f.repo, "snapshots", &old.id),
        "dry run must not mutate"
    );
    let report = f
        .repo
        .maintenance_execute(&plan, &plan.confirmation)
        .unwrap();
    assert_eq!(report.snapshots_removed, 1);
    assert_eq!(report.chunks_removed, 1);
    f.repo.verify(&retained.id).unwrap();
    f.repo.verify(&newest.id).unwrap();
    let destination = f._temp.path().join("restored");
    fs::create_dir(&destination).unwrap();
    let restore = f.repo.plan(&retained.id, &destination, None).unwrap();
    f.repo
        .restore(&retained.id, &destination, None, &restore.confirmation)
        .unwrap();
    assert_eq!(
        fs::read_to_string(destination.join("file")).unwrap(),
        "retained unique"
    );
}

#[test]
fn newest_survives_even_when_every_snapshot_exceeds_retention() {
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    let newest = f.snapshot("newest but old", 50);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert_eq!(plan.snapshots, [old.id]);
    assert_eq!(plan.retained_snapshots, std::slice::from_ref(&newest.id));
    f.execute();
    f.repo.verify(&newest.id).unwrap();
}

#[test]
fn pending_frozen_intent_and_active_journal_pin_their_snapshots() {
    let f = Fixture::new();
    let pending = f.snapshot("pending", 70);
    let frozen = f.snapshot("frozen", 65);
    let intent = f.snapshot("intent", 60);
    let active = f.snapshot("active", 55);
    f.snapshot("newest", 0);
    f.repo
        .save_request(
            &json!({"status":"pending", "expires_at":now()+900, "plan":{"snapshot":pending.id}}),
        )
        .unwrap();
    // Frozen bridge records stay pinned even when their local TTL has elapsed.
    f.repo
        .save_request(
            &json!({"frozen":{"plan":{"snapshot":frozen.id}}, "expires_at":"2000-01-01T00:00:00Z"}),
        )
        .unwrap();
    f.repo
        .save_request(&json!({"bridge_intent":{"plan":{"snapshot":intent.id}}}))
        .unwrap();
    let transaction = "a".repeat(64);
    f.encrypted(
        &format!("transactions/{transaction}/journal"),
        &json!({"id":transaction,"status":"interrupted","plan":{"snapshot":active.id}}),
        transaction.as_bytes(),
    );
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert!(plan.snapshots.is_empty());
    assert!(plan.chunks.is_empty());
    assert!(plan.requests.is_empty());
    f.execute();
    for snapshot in [&pending, &frozen, &intent, &active] {
        f.repo.verify(&snapshot.id).unwrap();
    }
    assert!(exists(&f.repo, "transactions", &transaction));
}

#[test]
fn decided_and_expired_local_requests_are_pruned_after_authentication() {
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    f.snapshot("newest", 0);
    let mut ids = vec![];
    for status in ["pending", "denied", "approved", "expired"] {
        ids.push(
            f.repo
                .save_request(
                    &json!({"status":status, "expires_at":now()-1, "plan":{"snapshot":old.id}}),
                )
                .unwrap(),
        );
    }
    let report = f.execute();
    assert_eq!(report.requests_removed, 4);
    assert_eq!(report.snapshots_removed, 1);
    for id in ids {
        assert!(!exists(&f.repo, "requests", &id));
    }
}

#[test]
fn corrupt_manifest_or_request_refuses_all_deletion() {
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    f.snapshot("newest", 0);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    let path = f.repo.root().join("snapshots").join(&old.id);
    let good = fs::read(&path).unwrap();
    fs::write(&path, b"corrupt manifest").unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    assert!(f
        .repo
        .maintenance_execute(&plan, &plan.confirmation)
        .is_err());
    assert!(exists(&f.repo, "chunks", &file_chunk(&old)));
    assert!(!f.repo.root().join("maintenance-journal").exists());
    fs::write(path, good).unwrap();
    fs::write(
        f.repo.root().join("requests").join("a".repeat(64)),
        b"bad request",
    )
    .unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    assert!(exists(&f.repo, "snapshots", &old.id));
}

#[test]
fn inventory_changes_and_forged_confirmations_are_rejected_without_deletion() {
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    f.snapshot("newest", 0);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert!(f.repo.maintenance_execute(&plan, "wrong").is_err());
    let mut forged = plan.clone();
    forged.retention_days = 1;
    assert!(f
        .repo
        .maintenance_execute(&forged, &plan.confirmation)
        .is_err());
    let _: bunker::repository::MaintenancePlan =
        serde_json::from_slice(&serde_json::to_vec(&plan).unwrap()).unwrap();
    f.orphan(b"new orphan invalidates inventory", 0);
    assert!(f
        .repo
        .maintenance_execute(&plan, &plan.confirmation)
        .is_err());
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    f.snapshot("another snapshot invalidates inventory", 0);
    assert!(f
        .repo
        .maintenance_execute(&plan, &plan.confirmation)
        .is_err());
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    fs::create_dir(f.repo.root().join("transactions")).unwrap();
    assert!(f
        .repo
        .maintenance_execute(&plan, &plan.confirmation)
        .is_err());
    assert!(exists(&f.repo, "snapshots", &old.id));
}

#[test]
fn orphan_and_temporary_cleanup_respects_grace_and_does_not_touch_checkpoints() {
    let f = Fixture::new();
    let snapshot = f.snapshot("retained", 0);
    let old = f.orphan(b"old failed snapshot chunk", 172800);
    let fresh = f.orphan(b"fresh failed snapshot chunk", 0);
    let old_temp = format!("snapshots/.bunker-{}.tmp", "b".repeat(32));
    let fresh_temp = format!("chunks/.bunker-{}.tmp", "c".repeat(32));
    fs::write(
        f.repo.root().join(&old_temp),
        b"incomplete temporary ciphertext",
    )
    .unwrap();
    aged(&f.repo.root().join(&old_temp), 172800);
    fs::write(
        f.repo.root().join(&fresh_temp),
        b"recent temporary ciphertext",
    )
    .unwrap();
    fs::create_dir(f.repo.root().join("checkpoints")).unwrap();
    fs::write(
        f.repo.root().join("checkpoints/untouched"),
        b"independent checkpoint",
    )
    .unwrap();
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert_eq!(plan.chunks, std::slice::from_ref(&old));
    assert_eq!(plan.temporary_files, std::slice::from_ref(&old_temp));
    f.execute();
    assert!(!exists(&f.repo, "chunks", &old));
    assert!(exists(&f.repo, "chunks", &fresh));
    assert!(f.repo.root().join(fresh_temp).exists());
    assert!(!f.repo.root().join(old_temp).exists());
    assert_eq!(
        fs::read(f.repo.root().join("checkpoints/untouched")).unwrap(),
        b"independent checkpoint"
    );
    f.repo.verify(&snapshot.id).unwrap();
}

#[test]
fn interrupted_manifest_first_deletion_requires_fresh_confirmation_and_rolls_forward() {
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    let newest = f.snapshot("newest", 0);
    aged(&f.repo.root().join("chunks").join(file_chunk(&old)), 172800);
    let original = f.repo.maintenance_plan(&Policy::default()).unwrap();
    // Simulate a crash after the durable journal and manifest unlink, before chunk unlink.
    f.encrypted(
        "maintenance-journal",
        &json!({"version":1,"plan":original}),
        b"bunker-local-maintenance-v1",
    );
    fs::remove_file(f.repo.root().join("snapshots").join(&old.id)).unwrap();
    let path = f.repo.root().to_path_buf();
    drop(f.repo);
    let reopened = Repository::open(&path, PASSPHRASE).unwrap();
    // Reopening never resumes deletion implicitly, even with a valid old journal.
    assert!(exists(&reopened, "chunks", &file_chunk(&old)));
    assert!(reopened
        .maintenance_execute(&original, &original.confirmation)
        .is_err());
    let resumed = reopened.maintenance_plan(&Policy::default()).unwrap();
    assert!(resumed.interrupted);
    assert_eq!(resumed.chunks, [file_chunk(&old)]);
    let report = reopened
        .maintenance_execute(&resumed, &resumed.confirmation)
        .unwrap();
    assert!(report.resumed);
    assert!(!reopened.root().join("maintenance-journal").exists());
    reopened.verify(&newest.id).unwrap();
}

#[test]
fn missing_or_unknown_restore_journal_fails_closed() {
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    f.snapshot("newest", 0);
    let id = "a".repeat(64);
    fs::create_dir_all(f.repo.root().join("transactions").join(&id)).unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    f.encrypted(
        &format!("transactions/{id}/journal"),
        &json!({"id":id,"status":"unrecognized","plan":{"snapshot":old.id}}),
        id.as_bytes(),
    );
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    assert!(exists(&f.repo, "chunks", &file_chunk(&old)));
}

#[test]
fn git_only_references_participate_in_reachability() {
    let f = Fixture::new();
    let old = f.snapshot("only referenced by retained Git metadata", 60);
    let mut newest = f.snapshot("new", 0);
    let file = old.files.iter().find(|file| file.path == "file").unwrap();
    newest.git = Some(bunker::repository::GitArtifact {
        version: 1,
        metadata: bunker::repository::GitPart {
            size: file.size,
            hash: file.hash.clone(),
            chunks: file.chunks.clone(),
        },
        pack: bunker::repository::GitPart {
            size: 0,
            hash: blake3::keyed_hash(&f.key, b"").to_hex().to_string(),
            chunks: vec![],
        },
    });
    f.manifest(&newest);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert_eq!(plan.snapshots, [old.id]);
    assert!(plan.chunks.is_empty());
    f.execute();
    assert!(exists(&f.repo, "chunks", &file.chunks[0]));
}

#[test]
fn unsupported_immutable_policy_and_ambiguous_inventory_do_not_delete() {
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    f.snapshot("newest", 0);
    let policy = Policy {
        immutable: true,
        ..Policy::default()
    };
    assert!(f.repo.maintenance_plan(&policy).is_err());
    let policy = Policy {
        retention_days: 0,
        ..Policy::default()
    };
    assert!(f.repo.maintenance_plan(&policy).is_err());
    fs::write(f.repo.root().join("snapshots/unknown"), b"unknown object").unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    assert!(exists(&f.repo, "snapshots", &old.id));
}

#[cfg(unix)]
#[test]
fn symlinked_files_and_directories_are_never_followed() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    f.snapshot("newest", 0);
    let outside = f._temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let payload = outside.join("payload");
    fs::write(&payload, b"must survive").unwrap();
    let malicious = f.repo.root().join("chunks").join("a".repeat(64));
    symlink(&payload, &malicious).unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    fs::remove_file(malicious).unwrap();
    symlink(&outside, f.repo.root().join("transactions")).unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    assert_eq!(fs::read(&payload).unwrap(), b"must survive");
    assert!(exists(&f.repo, "snapshots", &old.id));
}

#[test]
fn terminal_restore_journals_keep_rollback_inputs_and_preimages() {
    let f = Fixture::new();
    let old = f.snapshot("old but needed for rollback", 60);
    f.snapshot("newest", 0);
    let id = "d".repeat(64);
    f.encrypted(
        &format!("transactions/{id}/journal"),
        &json!({"id":id,"status":"completed","plan":{"snapshot":old.id}}),
        id.as_bytes(),
    );
    let preimage = f.repo.root().join(format!("transactions/{id}/0.before"));
    fs::write(
        &preimage,
        crypto::seal(&f.key, b"preimage", id.as_bytes()).unwrap(),
    )
    .unwrap();
    aged(&preimage, 172800);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert!(plan.snapshots.is_empty());
    f.execute();
    assert!(preimage.exists());
    f.repo.verify(&old.id).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinked_audit_directory_refuses_before_any_deletion() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    f.snapshot("newest", 0);
    let outside = f._temp.path().join("outside-audit");
    f.repo.audit("fixture", json!({})).unwrap();
    // Rename the fixture's existing audit directory, then install an alias to it.
    fs::rename(f.repo.root().join("audit"), &outside).unwrap();
    let count = fs::read_dir(&outside).unwrap().count();
    symlink(&outside, f.repo.root().join("audit")).unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    assert_eq!(fs::read_dir(outside).unwrap().count(), count);
    assert!(exists(&f.repo, "snapshots", &old.id));
}

#[test]
fn corrupt_journal_missing_chunks_and_oversized_objects_fail_closed() {
    let f = Fixture::new();
    let old = f.snapshot("old", 60);
    f.snapshot("newest", 0);
    fs::write(
        f.repo.root().join("maintenance-journal"),
        b"unauthenticated",
    )
    .unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    fs::remove_file(f.repo.root().join("maintenance-journal")).unwrap();
    let chunk = f.repo.root().join("chunks").join(file_chunk(&old));
    let bytes = fs::read(&chunk).unwrap();
    fs::remove_file(&chunk).unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    fs::write(&chunk, bytes).unwrap();
    let oversized = f.repo.root().join("chunks").join("e".repeat(64));
    fs::File::create(oversized)
        .unwrap()
        .set_len(9 * 1024 * 1024)
        .unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
    assert!(exists(&f.repo, "snapshots", &old.id));
}

fn setup_scope(
    f: &Fixture,
    label: &str,
    days: u64,
    group: char,
    index: u32,
    count: u32,
    root: &str,
) -> Manifest {
    let mut manifest = f.snapshot(label, days);
    manifest.agent = Some("codex".into());
    manifest.setup = Some(bunker::repository::SetupScope {
        version: 1,
        source_root: PathBuf::from(root),
        agents: vec![bunker_discovery::AgentId::Codex],
        capture_id: group.to_string().repeat(64),
        scope_index: index,
        scope_count: count,
        session_event: None,
    });
    f.manifest(&manifest);
    manifest
}

#[test]
fn retention_keeps_latest_per_agent_and_session() {
    let f = Fixture::new();
    let mut old = f.snapshot("old codex", 80);
    old.agent = Some("codex".into());
    old.session = Some("one".into());
    f.manifest(&old);
    let mut replacement = f.snapshot("new codex", 70);
    replacement.agent = old.agent.clone();
    replacement.session = old.session.clone();
    f.manifest(&replacement);
    let mut other_session = f.snapshot("other session", 75);
    other_session.agent = old.agent.clone();
    other_session.session = Some("two".into());
    f.manifest(&other_session);
    let mut other_agent = f.snapshot("cursor", 90);
    other_agent.agent = Some("cursor".into());
    f.manifest(&other_agent);
    f.snapshot("unattributed latest", 0);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert_eq!(plan.snapshots, [old.id]);
    for id in [replacement.id, other_session.id, other_agent.id] {
        assert!(plan.retained_snapshots.contains(&id));
    }
    f.repo
        .maintenance_execute(&plan, &plan.confirmation)
        .unwrap();
}

#[test]
fn retention_preserves_complete_setup_groups_and_incomplete_publications() {
    let f = Fixture::new();
    let expired = setup_scope(&f, "obsolete", 100, 'a', 0, 1, "/fixture/a");
    let a = setup_scope(&f, "complete a", 90, 'b', 0, 2, "/fixture/a");
    let b = setup_scope(&f, "complete b", 90, 'b', 1, 2, "/fixture/b");
    let replacement_a = setup_scope(&f, "new a", 80, 'c', 0, 1, "/fixture/a");
    let partial_b = setup_scope(&f, "partial b", 70, 'd', 0, 2, "/fixture/b");
    f.snapshot("latest workspace", 0);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert_eq!(plan.snapshots, [expired.id]);
    for id in [a.id, b.id, replacement_a.id, partial_b.id] {
        assert!(plan.retained_snapshots.contains(&id));
    }
    f.repo
        .maintenance_execute(&plan, &plan.confirmation)
        .unwrap();
}

#[test]
fn retention_does_not_split_a_setup_group_at_the_cutoff() {
    let f = Fixture::new();
    let a = setup_scope(&f, "old sibling", 31, 'a', 0, 2, "/fixture/a");
    let b = setup_scope(&f, "recent sibling", 29, 'a', 1, 2, "/fixture/b");
    setup_scope(&f, "new a", 20, 'b', 0, 1, "/fixture/a");
    setup_scope(&f, "new b", 20, 'c', 0, 1, "/fixture/b");
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert!(plan.snapshots.is_empty());
    assert!(plan.retained_snapshots.contains(&a.id));
    assert!(plan.retained_snapshots.contains(&b.id));
}

#[test]
fn pending_host_and_scheduler_delivery_pin_old_snapshots_and_stale_plans() {
    let f = Fixture::new();
    let queued = f.snapshot("undelivered", 100);
    let setup = f.snapshot("setup pending", 90);
    let detection = f.snapshot("detection pending", 80);
    f.snapshot("latest", 0);
    let original = f.repo.maintenance_plan(&Policy::default()).unwrap();
    f.encrypted("host/schedule", &json!({"workspace":"/fixture","host":null,"next_run":0,"last_snapshot":null,"pending":[queued.id],"pending_setup":setup.id,"pending_alerts":[]}), b"bunker-host-schedule-v1");
    let state = bunker::scheduler::ScheduleState {
        pending_detection: Some((Some(detection.id.clone()), setup.id.clone())),
        ..Default::default()
    };
    fs::write(
        f.repo.root().join("schedule.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    assert!(f
        .repo
        .maintenance_execute(&original, &original.confirmation)
        .is_err());
    let pinned = f.repo.maintenance_plan(&Policy::default()).unwrap();
    assert!(pinned.snapshots.is_empty());
    assert!(pinned.retained_snapshots.contains(&queued.id));
    fs::write(f.repo.root().join("schedule.json"), b"corrupt").unwrap();
    assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
}

#[test]
fn malformed_host_state_refuses_planning_and_execution() {
    let f = Fixture::new();
    f.snapshot("old", 100);
    f.snapshot("latest", 0);
    let plan = f.repo.maintenance_plan(&Policy::default()).unwrap();
    for state in [
        json!({"pending":[null],"pending_alerts":[42]}),
        json!({"workspace":"/fixture","host":null,"next_run":0,"last_snapshot":null,"pending":[null],"pending_alerts":[]}),
        json!({"workspace":"/fixture","host":null,"next_run":0,"last_snapshot":null,"pending":[],"pending_alerts":[42]}),
    ] {
        f.encrypted("host/schedule", &state, b"bunker-host-schedule-v1");
        assert!(f.repo.maintenance_plan(&Policy::default()).is_err());
        assert!(f
            .repo
            .maintenance_execute(&plan, &plan.confirmation)
            .is_err());
    }
}
