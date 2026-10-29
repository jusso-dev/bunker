use bunker_discovery::*;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn fixture(platform: Platform) -> (TempDir, DiscoveryContext) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let home = root.join("home");
    let workspace = root.join("workspace");
    let mut context = DiscoveryContext::new(platform, home.clone(), vec![workspace.clone()]);
    let editor = match platform {
        Platform::Linux => {
            context.config_dir = Some(root.join("xdg"));
            root.join("xdg")
        }
        Platform::MacOs => home.join("Library/Application Support"),
        Platform::Windows => {
            context.app_data = Some(root.join("roaming"));
            root.join("roaming")
        }
    };
    let layout: Value =
        serde_json::from_str(include_str!("../../../fixtures/discovery/layout.json")).unwrap();
    for (section, target) in [("home", home), ("workspace", workspace), ("editor", editor)] {
        for (relative, text) in layout[section].as_object().unwrap() {
            write(&target, relative, text.as_str().unwrap());
        }
    }
    (temp, context)
}

#[test]
fn five_agents_on_three_platform_layouts_and_safe_preparation() {
    for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
        let (_temp, context) = fixture(platform);
        let policy = SafetyPolicy::default();
        let results = discover(&context, &policy).unwrap();
        assert_eq!(results.len(), 5);
        let mut groups: BTreeMap<PathBuf, Vec<FileRequest>> = BTreeMap::new();
        for result in &results {
            assert!(!result.items.is_empty());
            assert!(result
                .session_signals
                .iter()
                .any(|s| s.source == SignalSource::ScheduledFallback));
            for item in &result.items {
                groups
                    .entry(item.root.clone())
                    .or_default()
                    .push(item.request());
            }
        }
        let claude = results
            .iter()
            .find(|r| r.agent == AgentId::ClaudeCode)
            .unwrap();
        for category in [
            ItemCategory::McpConfig,
            ItemCategory::Settings,
            ItemCategory::Skill,
            ItemCategory::Rule,
            ItemCategory::SubAgent,
            ItemCategory::Hook,
            ItemCategory::Memory,
        ] {
            assert!(
                claude.items.iter().any(|i| i.category == category),
                "missing {category:?}"
            );
        }
        assert!(results
            .iter()
            .flat_map(|r| &r.items)
            .any(|i| i.relative_path == Path::new("Cursor/User/settings.json")));
        for (root, requests) in groups {
            let snapshot = prepare_files(&root, &requests, &policy).unwrap();
            let serialized = serde_json::to_string(&snapshot).unwrap();
            for marker in [
                "fake-claude-credential",
                "fake-cursor-credential",
                "fake-codex-credential",
                "fake-copilot-credential",
                "fake-kiro-credential",
                "fake-editor-credential",
                "customer-fixture-data",
            ] {
                assert!(!serialized.contains(marker));
                for file in &snapshot.files {
                    assert!(!String::from_utf8_lossy(&file.bytes).contains(marker));
                }
            }
        }
    }
}

#[test]
fn missing_and_unknown_agents_are_normal() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let context = DiscoveryContext::new(Platform::Linux, home, vec![]);
    let registry = DiscoveryRegistry::default();
    assert!(registry.get_by_name("unknown").is_none());
    assert!(registry
        .discover(&context, &SafetyPolicy::default())
        .unwrap()
        .is_empty());
    assert!(registry
        .get(AgentId::Codex)
        .unwrap()
        .discover(&context, &SafetyPolicy::default())
        .unwrap()
        .items
        .is_empty());
}

#[test]
fn json_sanitizes_nested_secrets_env_headers_args_urls_and_preserves_refs() {
    let input = br#"{
        "mcpServers":{"one":{"command":"node","args":["--token","fake-argument-value"],
        "env":{"TOKEN":"fake-env-value","FROM_VAULT":"vault://fixture/token"},
        "headers":{"Authorization":"fake-header-value"},"nested":{"password":42},
        "url":"https://example.test/mcp?token=fake-query-value"}},
        "ordinary":"ghp_fixtureValue123", "model":"fixture-model", "history":["customer-data"]
    }"#;
    let result = sanitize(input, FileFormat::Json).unwrap();
    let text = String::from_utf8(result.bytes).unwrap();
    for removed in [
        "fake-argument-value",
        "fake-env-value",
        "fake-header-value",
        "fake-query-value",
        "ghp_fixtureValue123",
        "customer-data",
    ] {
        assert!(!text.contains(removed));
    }
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["model"], "fixture-model");
    assert_eq!(parsed["mcpServers"]["one"]["args"][0], "--token");
    assert!(result
        .secret_references
        .iter()
        .any(|r| r.reference == "vault://fixture/token" && r.kind == ReferenceKind::Existing));
    assert!(result
        .secret_references
        .iter()
        .any(|r| r.location.ends_with("/nested/password")));
}

#[test]
fn toml_is_valid_after_sanitization() {
    let input = b"model = 'fixture-model'\n[mcp_servers.fixture]\napi_key = 'fake-toml-value'\n[mcp_servers.fixture.env]\nEXISTING = '${env:FIXTURE_KEY}'\n";
    let result = sanitize(input, FileFormat::Toml).unwrap();
    let text = String::from_utf8(result.bytes).unwrap();
    let parsed: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(parsed["model"].as_str(), Some("fixture-model"));
    assert!(!text.contains("fake-toml-value"));
    assert!(text.contains("${env:FIXTURE_KEY}"));
}

#[test]
fn malformed_configs_and_binary_data_fail_closed_without_leaking_diagnostics() {
    for (input, format) in [
        (
            b"{\"apiKey\": fake-parser-secret".as_slice(),
            FileFormat::Json,
        ),
        (b"api_key = fake-parser-secret".as_slice(), FileFormat::Toml),
        (b"[1,2]".as_slice(), FileFormat::Json),
        (b"\xff\xfe".as_slice(), FileFormat::Text),
        (b"hello\0world".as_slice(), FileFormat::Text),
    ] {
        let error = sanitize(input, format).unwrap_err();
        assert!(!format!("{error:#}").contains("fake-parser-secret"));
    }
}

#[test]
fn text_secrets_and_private_key_material_are_not_copied() {
    let result = sanitize(b"# Instructions\nexport API_KEY=fake-text-value # fake-comment-value\nAuthorization: Bearer fixture-bearer-value\nUse focused tests.\n", FileFormat::Text).unwrap();
    let text = String::from_utf8(result.bytes).unwrap();
    assert!(text.contains("# Instructions\n"));
    assert!(text.contains("Use focused tests."));
    assert!(!text.contains("fake-text-value"));
    assert!(!text.contains("fake-comment-value"));
    assert!(!text.contains("fixture-bearer-value"));
    assert_eq!(result.secret_references.len(), 2);
    assert!(sanitize(
        b"-----BEGIN PRIVATE KEY-----\nfixture-only\n",
        FileFormat::Text
    )
    .is_err());
}

#[test]
fn inline_assignments_cannot_hide_after_a_safe_assignment_or_in_json_prose() {
    for (input, format) in [
        (
            b"MODE=safe API_KEY=fake-inline-secret".as_slice(),
            FileFormat::Text,
        ),
        (
            br#"{"notes":"MODE=safe API_KEY=fake-inline-secret"}"#.as_slice(),
            FileFormat::Json,
        ),
    ] {
        let output = sanitize(input, format).unwrap();
        assert!(!String::from_utf8_lossy(&output.bytes).contains("fake-inline-secret"));
    }
}

#[test]
fn multiline_text_credentials_fail_closed() {
    for text in [
        "password: |\n  fixture-secret\n",
        "token = \"\nfixture-secret\n\"\n",
        "secret = \\\nfixture-secret\n",
        "api_key:\n  fixture-secret\n",
    ] {
        let error = sanitize(text.as_bytes(), FileFormat::Text).unwrap_err();
        assert!(!format!("{error:#}").contains("fixture-secret"));
    }
}

#[cfg(windows)]
#[test]
fn windows_native_relative_path_separators_are_supported() {
    assert!(
        validate_relative_path(&PathBuf::from(".claude").join("skills").join("SKILL.md")).is_ok()
    );
}

#[test]
fn defaults_exclude_sensitive_and_bulk_files_without_reading_them() {
    let policy = SafetyPolicy::default();
    let exclusions = ExclusionPolicy::new(&policy).unwrap();
    for path in [
        ".env",
        ".env.local",
        "nested/.env.example",
        "auth.json",
        ".ssh/id_rsa",
        "cert.pem",
        ".claude/projects/work/memory.md",
        ".codex/sessions/rollout.jsonl",
        "history.jsonl",
        "node_modules/pkg/index.js",
        ".git/objects/object",
        ".cache/data",
        "target/debug/app",
        "weights.safetensors",
        "database.sqlite",
    ] {
        assert!(
            exclusions.reason(Path::new(path)).unwrap().is_some(),
            "not excluded: {path}"
        );
    }
    for path in [
        "src/lib.rs",
        "projects/app/main.rs",
        ".claude/skills/review/SKILL.md",
        ".cursor/mcp.json",
        ".codex/config.toml",
    ] {
        assert!(
            exclusions.reason(Path::new(path)).unwrap().is_none(),
            "unexpected exclusion: {path}"
        );
    }
    // Exclusion happens before attempting a filesystem read, even for missing roots.
    assert!(prepare_file(
        Path::new("/does-not-exist"),
        &FileRequest::new(".env"),
        &policy
    )
    .unwrap()
    .is_none());
}

#[test]
fn extra_policy_exclusions_match_directories_and_invalid_globs_error() {
    let policy = SafetyPolicy {
        extra_excludes: vec!["private".into(), "**/*.sensitive".into()],
        ..SafetyPolicy::default()
    };
    let exclusions = ExclusionPolicy::new(&policy).unwrap();
    assert_eq!(
        exclusions.reason(Path::new("private/data.txt")).unwrap(),
        Some(ExclusionReason::Policy)
    );
    assert_eq!(
        exclusions
            .reason(Path::new("nested/file.sensitive"))
            .unwrap(),
        Some(ExclusionReason::Policy)
    );
    assert!(ExclusionPolicy::new(&SafetyPolicy {
        extra_excludes: vec!["[".into()],
        ..policy
    })
    .is_err());
}

#[test]
fn traversal_and_foreign_platform_absolute_paths_are_rejected() {
    for path in [
        "",
        "../secret",
        "a/../secret",
        "./file",
        "/etc/passwd",
        "C:\\secret",
        "C:/secret",
        "a\\..\\secret",
        "//host/share",
        "a//file",
        "a/./file",
    ] {
        assert!(
            validate_relative_path(Path::new(path)).is_err(),
            "accepted {path}"
        );
    }
    assert!(validate_relative_path(Path::new(".claude/settings.json")).is_ok());
}

#[test]
fn repository_cap_is_atomic_and_counts_deduplicated_source_and_output() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    write(&root, "one.md", "12345");
    write(&root, "two.md", "67890");
    let policy = SafetyPolicy {
        max_file_bytes: 8,
        max_repo_bytes: 9,
        ..SafetyPolicy::default()
    };
    let requests = [FileRequest::new("one.md"), FileRequest::new("two.md")];
    let error = prepare_files(&root, &requests, &policy).unwrap_err();
    assert!(error
        .to_string()
        .contains("repository exceeds configured size cap"));
    let one = prepare_files(&root, &[requests[0].clone(), requests[0].clone()], &policy).unwrap();
    assert_eq!(one.source_bytes, 5);
    assert_eq!(one.files.len(), 1);
    write(&root, "huge.md", "123456789");
    assert!(prepare_file(&root, &FileRequest::new("huge.md"), &policy).is_err());
    write(&root, "payload.md", "token=x");
    assert_eq!(
        prepare_file(&root, &FileRequest::new("payload.md"), &policy)
            .unwrap()
            .unwrap()
            .bytes,
        b"token=x"
    );
}

#[test]
fn config_extension_cannot_be_downgraded_to_text() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    write(&root, ".mcp.json", "{invalid credential config");
    let request = FileRequest {
        relative_path: ".mcp.json".into(),
        format: FileFormat::Text,
    };
    assert!(prepare_file(&root, &request, &SafetyPolicy::default()).is_err());
}

#[test]
fn signal_contract_distinguishes_turns_from_sessions() {
    let registry = DiscoveryRegistry::default();
    let claude = registry.get(AgentId::ClaudeCode).unwrap().session_signals();
    assert!(claude
        .iter()
        .any(|s| s.event == SessionEvent::SessionEnd && s.source == SignalSource::NativeHook));
    for id in [
        AgentId::Cursor,
        AgentId::Codex,
        AgentId::GitHubCopilot,
        AgentId::Kiro,
    ] {
        let signals = registry.get(id).unwrap().session_signals();
        assert!(!signals
            .iter()
            .any(|s| s.event == SessionEvent::SessionEnd && s.source == SignalSource::NativeHook));
        assert!(signals
            .iter()
            .any(|s| s.event == SessionEvent::SessionEnd
                && s.source == SignalSource::ExternalLifecycle));
    }
}

#[cfg(unix)]
#[test]
fn symlink_file_directory_root_and_ancestor_are_rejected() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    write(&root, "outside/payload.md", "fixture-only-outside");
    fs::create_dir(root.join("repo")).unwrap();
    symlink(root.join("outside/payload.md"), root.join("repo/file.md")).unwrap();
    symlink(root.join("outside"), root.join("repo/linked")).unwrap();
    symlink(root.join("repo"), root.join("alias")).unwrap();
    let policy = SafetyPolicy::default();
    assert!(prepare_file(&root.join("repo"), &FileRequest::new("file.md"), &policy).is_err());
    assert!(prepare_file(
        &root.join("repo"),
        &FileRequest::new("linked/payload.md"),
        &policy
    )
    .is_err());
    assert!(prepare_file(&root.join("alias"), &FileRequest::new("file.md"), &policy).is_err());
    fs::create_dir_all(root.join("repo/nested")).unwrap();
    assert!(prepare_file(
        &root.join("alias/nested"),
        &FileRequest::new("file.md"),
        &policy
    )
    .is_err());
    fs::create_dir_all(root.join("home/.claude")).unwrap();
    symlink(root.join("outside"), root.join("home/.claude/skills")).unwrap();
    let context = DiscoveryContext::new(Platform::Linux, root.join("home"), vec![]);
    let found = discover(&context, &policy).unwrap();
    assert!(found
        .iter()
        .flat_map(|r| &r.excluded)
        .any(|e| e.relative_path == Path::new(".claude/skills")
            && e.reason == ExclusionReason::UnsafePath));
}

#[cfg(unix)]
#[test]
fn fifo_is_rejected_without_blocking() {
    use std::os::unix::ffi::OsStrExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = std::ffi::CString::new(root.join("pipe.md").as_os_str().as_bytes()).unwrap();
    // Test-only named pipe; no contents or real configuration are involved.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(prepare_file(
        &root,
        &FileRequest::new("pipe.md"),
        &SafetyPolicy::default()
    )
    .is_err());
}

#[test]
fn history_removal_is_semantic_modification_without_secret_references() {
    let sanitized = bunker_discovery::sanitize(
        br#"{"history":["fixture"],"messages":["fixture"],"projects":{"x":{}}}"#,
        bunker_discovery::FileFormat::Json,
    )
    .unwrap();
    assert!(sanitized.modified);
    assert!(sanitized.secret_references.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sanitized.bytes).unwrap(),
        serde_json::json!({})
    );
    let original = b"{ \"apiKey\": \"${EXISTING}\", \"theme\": \"dark\" }\n";
    let sanitized =
        bunker_discovery::sanitize(original, bunker_discovery::FileFormat::Json).unwrap();
    assert!(!sanitized.modified);
    assert_eq!(sanitized.bytes, original);
    assert_eq!(sanitized.secret_references.len(), 1);
}

#[test]
fn sanitizer_refuses_large_input_before_parsing() {
    let oversized = vec![b' '; 1024 * 1024 + 1];
    assert!(
        bunker_discovery::sanitize(&oversized, bunker_discovery::FileFormat::Json)
            .unwrap_err()
            .to_string()
            .contains("1 MiB")
    );
}

#[test]
fn discovery_reports_excluded_setup_candidates_even_when_no_files_remain() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let home = root.join("home");
    write(
        &home,
        ".claude/skills/logs/private.jsonl",
        "private fixture",
    );
    let context = DiscoveryContext::new(Platform::Linux, home.clone(), vec![]);
    let results = discover(&context, &SafetyPolicy::default()).unwrap();
    let claude = results
        .iter()
        .find(|r| r.agent == AgentId::ClaudeCode)
        .unwrap();
    assert!(claude.items.is_empty());
    assert!(claude.excluded.iter().any(|e| e.root == home
        && e.relative_path == Path::new(".claude/skills/logs/private.jsonl")
        && e.reason == ExclusionReason::Transcript));
}

#[test]
fn r2_assets_byte_exact_and_malformed_config_isolated() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let assets: &[(&str, &[u8])] = &[
        (".claude/skills/pdf/logo.png", b"\x89PNG\r\n\x1a\n\0\xff"),
        (
            ".claude/commands/history.md",
            b"token=fixture-documentation\n",
        ),
        (
            ".claude/skills/chat/settings.json",
            b"{ordinary source jsonc // fixture}",
        ),
    ];
    let mut requests = vec![];
    for (path, bytes) in assets {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), bytes).unwrap();
        requests.push(FileRequest::new(path));
    }
    write(&root, "apps/web/.mcp.json", "{malformed fixture");
    requests.push(FileRequest::new("apps/web/.mcp.json"));
    let prepared = prepare_files(&root, &requests, &SafetyPolicy::default()).unwrap();
    assert_eq!(prepared.files.len(), assets.len());
    for (path, bytes) in assets {
        assert_eq!(
            &prepared
                .files
                .iter()
                .find(|f| f.relative_path == Path::new(path))
                .unwrap()
                .bytes,
            bytes
        );
    }
    assert!(prepared
        .excluded
        .iter()
        .any(|(p, r)| p == Path::new("apps/web/.mcp.json")
            && *r == ExclusionReason::InvalidConfiguration));
}

#[cfg(unix)]
#[test]
fn r2_symlink_does_not_abort_unrelated_agent_discovery_or_preparation() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    write(&root, "home/.claude/skills/pdf/SKILL.md", "fixture");
    write(&root, "home/.cursor/rules/a.mdc", "fixture rule");
    write(&root, "outside/SKILL.md", "outside fixture");
    symlink(
        root.join("outside"),
        root.join("home/.claude/skills/linked"),
    )
    .unwrap();
    let results = discover(
        &DiscoveryContext::new(Platform::current(), root.join("home"), vec![]),
        &SafetyPolicy::default(),
    )
    .unwrap();
    assert!(results
        .iter()
        .any(|r| r.agent == AgentId::Cursor && !r.items.is_empty()));
    assert!(results.iter().any(|r| r.agent == AgentId::ClaudeCode
        && r.items.len() == 1
        && r.excluded
            .iter()
            .any(|e| e.reason == ExclusionReason::UnsafePath)));
    let prepared = prepare_files(
        &root.join("home"),
        &[
            FileRequest::new(".claude/skills/linked/SKILL.md"),
            FileRequest::new(".claude/skills/pdf/SKILL.md"),
        ],
        &SafetyPolicy::default(),
    )
    .unwrap();
    assert_eq!(prepared.files.len(), 1);
    assert_eq!(prepared.excluded.len(), 1);
}

#[test]
fn r2_any_url_query_and_userinfo_rebind_and_toml_datetime_survives() {
    for url in [
        "https://h.example/mcp?key=fixture",
        "https://h.example/mcp?sig=fixture",
        "https://h.example/mcp?auth=fixture",
        "https://fixture@h.example/mcp",
        "https://h.example/mcp?page=1",
    ] {
        let raw = serde_json::to_vec(&serde_json::json!({"url":url})).unwrap();
        let sanitized = sanitize(&raw, FileFormat::Json).unwrap();
        assert!(sanitized.modified, "URL not rebound: {url}");
        assert_eq!(
            sanitized.secret_references[0].kind,
            ReferenceKind::RebindRequired
        );
        assert!(!String::from_utf8(sanitized.bytes).unwrap().contains(url));
    }
    let sanitized = sanitize(
        b"created = 1979-05-27T07:32:00Z\n[mcp_servers.x.env]\nK = \"fixture\"\n",
        FileFormat::Toml,
    )
    .unwrap();
    let parsed: toml::Value =
        toml::from_str(std::str::from_utf8(&sanitized.bytes).unwrap()).unwrap();
    assert!(parsed["created"].is_datetime());
}

#[test]
fn r2_case_collisions_include_directory_aliases_and_report_skips() {
    let mut identities = PathIdentitySet::default();
    assert!(identities.insert(Path::new("Docs/one.md")));
    assert!(!identities.insert(Path::new("docs/two.md")));
    assert!(identities.insert(Path::new("Docs/three.md")));
    assert!(!identities.insert(Path::new("Docs/ONE.md")));
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    write(&root, "one.md", "fixture");
    let prepared = prepare_files(
        &root,
        &[FileRequest::new("one.md"), FileRequest::new("ONE.md")],
        &SafetyPolicy::default(),
    )
    .unwrap();
    assert_eq!(prepared.files.len(), 1);
    assert_eq!(
        prepared.excluded,
        vec![(PathBuf::from("ONE.md"), ExclusionReason::CaseCollision)]
    );
}

#[test]
fn canonical_unicode_path_aliases_are_refused_without_a_filesystem_dependency() {
    let mut identities = PathIdentitySet::default();
    assert!(identities.insert(Path::new("café/source.rs")));
    assert!(!identities.insert(Path::new("cafe\u{301}/other.rs")));
    assert!(!identities.insert(Path::new("CAFÉ/source.rs")));
    assert!(identities.insert(Path::new("café/other.rs")));
    assert!(identities.insert(Path::new("ordinary/é.txt")));
    assert!(!identities.insert(Path::new("ordinary/e\u{301}.txt")));
}
