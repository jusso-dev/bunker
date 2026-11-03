//! Disposable fixture roots only: CLI discovery grouping, session capture and
//! session rollback, the MCP tool boundary, and CLI reference coverage.
use bunker::{
    policy::Policy,
    repository::{Repository, SESSION_END, SESSION_ROLLBACK, SESSION_START},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const PASS: &str = "cli-acceptance-fixture";

fn put(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}
struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    work: PathBuf,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (home, work) = (root.join("home"), root.join("work"));
    fs::create_dir(&home).unwrap();
    fs::create_dir(&work).unwrap();
    let repo = root.join("repo");
    Repository::init(&repo, PASS).unwrap();
    Fixture {
        _temp: temp,
        repo,
        home,
        work,
    }
}
fn bunker(repo: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bunker"));
    command
        .arg("--repo")
        .arg(repo)
        .env("BUNKER_PASSPHRASE", PASS);
    command
}
fn documents(output: &Output) -> Vec<Value> {
    serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<Result<_, _>>()
        .unwrap()
}
fn success(output: Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    documents(&output)
}
fn list(repo: &Path) -> Vec<Value> {
    let output = success(bunker(repo).arg("list").output().unwrap());
    output[0].as_array().unwrap().clone()
}

#[test]
fn discover_groups_items_by_category_and_keeps_existing_fields() {
    let f = fixture();
    put(&f.home, ".claude/settings.json", r#"{"theme":"dark"}"#);
    put(&f.home, ".claude/skills/review/SKILL.md", "Review.\n");
    put(&f.home, ".codex/config.toml", "model = \"fixture\"\n");
    put(&f.work, ".cursor/environment.json", r#"{"install":"make"}"#);
    let output = Command::new(env!("CARGO_BIN_EXE_bunker"))
        .args(["discover", "--home"])
        .arg(&f.home)
        .arg("--workspace")
        .arg(&f.work)
        .env_remove("BUNKER_PASSPHRASE")
        .output()
        .unwrap();
    let results = success(output)[0].as_array().unwrap().clone();
    let agent = |name: &str| {
        results
            .iter()
            .find(|r| r["agent"] == name)
            .unwrap_or_else(|| panic!("{name} missing"))
            .clone()
    };
    let claude = agent("claude_code");
    for field in [
        "items",
        "workspace_roots",
        "session_signals",
        "excluded",
        "by_category",
    ] {
        assert!(claude.get(field).is_some(), "{field} missing");
    }
    let path = |root: &Path, relative: &str| json!(root.join(relative));
    assert_eq!(
        claude["by_category"]["settings"],
        json!([path(&f.home, ".claude/settings.json")])
    );
    assert_eq!(
        claude["by_category"]["skill"],
        json!([path(&f.home, ".claude/skills/review/SKILL.md")])
    );
    assert_eq!(
        agent("codex")["by_category"],
        json!({"settings":[path(&f.home, ".codex/config.toml")]})
    );
    assert_eq!(
        agent("cursor")["by_category"]["settings"],
        json!([path(&f.work, ".cursor/environment.json")])
    );
    for result in &results {
        let grouped: usize = result["by_category"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_array().unwrap().len())
            .sum();
        assert_eq!(grouped, result["items"].as_array().unwrap().len());
    }
}

#[test]
fn claude_session_end_hook_payload_creates_a_listed_snapshot() {
    let f = fixture();
    put(&f.work, "src/main.rs", "fn main() {}\n");
    let mut child = bunker(&f.repo)
        .args(["session-end", "--agent", "claude-code", "--home"])
        .arg(&f.home)
        .arg("--workspace")
        .arg(&f.work)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Untrusted cwd/transcript fields are ignored; only the explicit workspace is captured.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            json!({"session_id":"claude-fixture-1","hook_event_name":"SessionEnd",
                "cwd":"/elsewhere","transcript_path":"/elsewhere/t.jsonl","reason":"exit"})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    let report = success(child.wait_with_output().unwrap());
    assert_eq!(report[0]["session"], "claude-fixture-1");
    let created = report[0]["workspace_snapshots"].as_array().unwrap();
    assert_eq!(created.len(), 1);
    let listed = list(&f.repo);
    let snapshot = listed
        .iter()
        .find(|m| m["id"] == created[0])
        .expect("session snapshot listed");
    assert_eq!(snapshot["trigger"], SESSION_END);
    assert_eq!(snapshot["session"], "claude-fixture-1");
    assert_eq!(snapshot["agent"], "claude_code");
    assert!(snapshot["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| file["path"] == "src/main.rs"));
    // A non-SessionEnd payload is refused without creating a snapshot.
    let mut child = bunker(&f.repo)
        .args(["session-end", "--agent", "claude-code", "--home"])
        .arg(&f.home)
        .arg("--workspace")
        .arg(&f.work)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"session_id":"claude-fixture-2","hook_event_name":"Stop"}"#)
        .unwrap();
    assert!(!child.wait_with_output().unwrap().status.success());
    assert_eq!(list(&f.repo).len(), listed.len());
}

#[cfg(unix)]
#[test]
fn session_run_captures_before_and_after_and_preserves_exit_status() {
    for (session, code) in [("codex-run-ok", 0), ("codex-run-fail", 3)] {
        let f = fixture();
        put(&f.work, "notes.txt", "before session\n");
        let output = bunker(&f.repo)
            .args(["session-run", "--agent", "codex", "--session-id", session])
            .arg("--home")
            .arg(&f.home)
            .arg("--workspace")
            .arg(&f.work)
            .args([
                "--",
                "/bin/sh",
                "-c",
                &format!("printf 'during session\\n' > \"$1\"; exit {code}"),
                "fixture",
            ])
            .arg(f.work.join("notes.txt"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = documents(&output);
        assert_eq!(report[0]["session"], session);
        assert_eq!(
            report[0]["workspace_snapshots"].as_array().unwrap().len(),
            1
        );
        let triggers: BTreeSet<_> = list(&f.repo)
            .iter()
            .filter(|m| m["session"] == session && m["agent"] == "codex")
            .map(|m| m["trigger"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            triggers,
            BTreeSet::from([SESSION_START.to_owned(), SESSION_END.to_owned()])
        );
    }
}

#[test]
fn session_rollback_cli_reviews_confirms_and_restores_pre_session_state() {
    let f = fixture();
    put(&f.work, "keep.txt", "untouched\n");
    put(&f.work, "edited.txt", "pre-session\n");
    put(&f.work, "removed.txt", "pre-session removed\n");
    let session = "rollback-fixture-1";
    success(
        bunker(&f.repo)
            .args(["snapshot", "--agent", "codex", "--session", session])
            .args(["--trigger", SESSION_START, "--workspace"])
            .arg(&f.work)
            .output()
            .unwrap(),
    );
    put(&f.work, "edited.txt", "agent edit\n");
    fs::remove_file(f.work.join("removed.txt")).unwrap();
    put(&f.work, "created.txt", "agent created\n");
    success(
        bunker(&f.repo)
            .args(["session-end", "--agent", "codex", "--session-id", session])
            .arg("--home")
            .arg(&f.home)
            .arg("--workspace")
            .arg(&f.work)
            .output()
            .unwrap(),
    );
    let review = |command: &str| {
        let mut cmd = bunker(&f.repo);
        cmd.args([command, "--session", session, "--workspace"])
            .arg(&f.work);
        cmd
    };
    let diff = success(review("diff").output().unwrap());
    let (rollback, plan) = (&diff[0], &diff[1]);
    assert_eq!(rollback["session"], session);
    assert_eq!(
        rollback["restored_paths"],
        json!(["edited.txt", "removed.txt"])
    );
    assert_eq!(rollback["created_during_session"], json!(["created.txt"]));
    assert_eq!(plan["snapshot"], rollback["rollback_snapshot"]);
    let actions: Vec<_> = plan["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["path"].as_str().unwrap(), c["action"].as_str().unwrap()))
        .collect();
    assert_eq!(
        actions,
        [("edited.txt", "overwrite"), ("removed.txt", "create")]
    );
    // Preview only without the confirmation token.
    let preview = success(review("restore").output().unwrap());
    assert_eq!(preview[1]["confirmation"], plan["confirmation"]);
    assert_eq!(
        fs::read_to_string(f.work.join("edited.txt")).unwrap(),
        "agent edit\n"
    );
    // A stale token is refused after the destination changes.
    put(&f.work, "edited.txt", "later edit\n");
    let stale = review("restore")
        .arg("--confirm")
        .arg(plan["confirmation"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert_eq!(
        fs::read_to_string(f.work.join("edited.txt")).unwrap(),
        "later edit\n"
    );
    let fresh = success(review("diff").output().unwrap());
    assert_eq!(fresh[0]["rollback_snapshot"], rollback["rollback_snapshot"]);
    let restored = success(
        review("restore")
            .arg("--confirm")
            .arg(fresh[1]["confirmation"].as_str().unwrap())
            .output()
            .unwrap(),
    );
    assert_eq!(restored.last().unwrap()["restored"], true);
    for (path, text) in [
        ("edited.txt", "pre-session\n"),
        ("removed.txt", "pre-session removed\n"),
        ("keep.txt", "untouched\n"),
        ("created.txt", "agent created\n"),
    ] {
        assert_eq!(fs::read_to_string(f.work.join(path)).unwrap(), text);
    }
    let listed = list(&f.repo);
    assert_eq!(
        listed
            .iter()
            .filter(|m| m["trigger"] == SESSION_ROLLBACK)
            .count(),
        1
    );
    assert!(!bunker(&f.repo)
        .args(["diff", "--session", "unknown-session", "--workspace"])
        .arg(&f.work)
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn session_rollback_requires_an_unambiguous_pre_session_baseline() {
    let f = fixture();
    let repo = Repository::open(&f.repo, PASS).unwrap();
    put(&f.work, "a.txt", "one\n");
    let capture = |trigger: &str| {
        repo.snapshot(
            &f.work,
            &Policy::default(),
            Some("codex".into()),
            Some("baseline-fixture".into()),
            trigger,
        )
        .unwrap()
    };
    // Without a session-start capture, a repository-wide predecessor is never inferred.
    repo.snapshot(&f.work, &Policy::default(), None, None, "schedule")
        .unwrap();
    capture(SESSION_END);
    assert!(repo.session_rollback("baseline-fixture", &f.work).is_err());
    capture(SESSION_START);
    // The session changed nothing.
    assert!(repo.session_rollback("baseline-fixture", &f.work).is_err());
    capture(SESSION_START);
    put(&f.work, "a.txt", "two\n");
    assert!(repo
        .session_rollback("baseline-fixture", &f.work)
        .unwrap_err()
        .to_string()
        .contains("ambiguous"));
}

#[test]
fn mcp_tools_list_is_exactly_the_non_destructive_tool_set() {
    let f = fixture();
    put(&f.work, "a.txt", "fixture\n");
    let repo = Repository::open(&f.repo, PASS).unwrap();
    let snapshot = repo
        .snapshot(&f.work, &Policy::default(), None, None, "manual")
        .unwrap();
    drop(repo);
    let forbidden = [
        "restore",
        "approve",
        "deny",
        "delete_snapshot",
        "prune_requests",
        "maintenance_execute",
        "rewrap_passphrase",
        "replicate",
    ];
    let mut input = vec![json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})];
    for (index, name) in forbidden.iter().enumerate() {
        input.push(json!({"jsonrpc":"2.0","id":index + 2,"method":"tools/call",
            "params":{"name":name,"arguments":{"snapshot":snapshot.id}}}));
    }
    let input: String = input.iter().map(|v| format!("{v}\n")).collect();
    let mut output = vec![];
    bunker::mcp::serve(
        &f.repo,
        PASS,
        &f.work,
        std::io::Cursor::new(input),
        &mut output,
    )
    .unwrap();
    let responses: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let tools: Vec<_> = responses[0]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(tools, ["list_snapshots", "diff", "request_restore"]);
    for response in &responses[1..] {
        assert_eq!(response["result"]["isError"], true);
    }
    let repo = Repository::open(&f.repo, PASS).unwrap();
    assert_eq!(repo.list().unwrap().len(), 1);
    repo.verify(&snapshot.id).unwrap();
    assert_eq!(
        fs::read_to_string(f.work.join("a.txt")).unwrap(),
        "fixture\n"
    );
}

/// Long flags listed under a help page's `Options:` heading.
fn help_flags(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|line| !line.starts_with("Options:"))
        .filter_map(|line| {
            let line = line.trim_start();
            let line = line.strip_prefix("-h, ").unwrap_or(line);
            let flag = line.strip_prefix("--")?;
            Some(
                flag.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                    .next()?
                    .to_owned(),
            )
        })
        .filter(|flag| !matches!(flag.as_str(), "help" | "version"))
        .collect()
}
/// Subcommand names listed under a help page's `Commands:` heading.
fn help_commands(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|line| !line.starts_with("Commands:"))
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
        .filter(|name| name != "help")
        .collect()
}
fn help(path: &[String]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bunker"))
        .args(path)
        .arg("--help")
        .env_remove("BUNKER_PASSPHRASE")
        .output()
        .unwrap();
    assert!(output.status.success(), "help failed for {path:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// Reference-table rows documenting `name` (`| \`name\`` or `| \`name ARG...\``).
fn doc_rows<'a>(docs: &'a str, name: &str) -> Vec<&'a str> {
    docs.lines()
        .filter(|line| {
            line.strip_prefix(&format!("| `{name}"))
                .is_some_and(|rest| rest.starts_with('`') || rest.starts_with(' '))
        })
        .collect()
}

#[test]
fn cli_reference_documents_every_subcommand_and_long_flag() {
    let docs =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/user/cli.md"))
            .unwrap();
    // Global flags are documented once, in their own table.
    let global = help_flags(&help(&[]));
    for flag in &global {
        assert!(
            doc_rows(&docs, &format!("--{flag}")).len() == 1,
            "global --{flag} undocumented"
        );
    }
    let mut missing = vec![];
    let mut visited = BTreeSet::new();
    let mut pending: Vec<Vec<String>> = help_commands(&help(&[]))
        .into_iter()
        .map(|c| vec![c])
        .collect();
    while let Some(path) = pending.pop() {
        let name = path.join(" ");
        let page = help(&path);
        // A flag counts only when the command's own row (or, for nested
        // commands, the parent's row) names it.
        let mut rows = doc_rows(&docs, &name);
        if rows.is_empty() {
            missing.push(name.clone());
        }
        rows.extend(doc_rows(&docs, &path[..path.len() - 1].join(" ")));
        for flag in help_flags(&page) {
            if !global.contains(&flag) && !rows.iter().any(|row| row.contains(&format!("--{flag}")))
            {
                missing.push(format!("{name} --{flag}"));
            }
        }
        for command in help_commands(&page) {
            let mut child = path.clone();
            child.push(command);
            pending.push(child);
        }
        visited.insert(name);
    }
    // The walk must reach nested commands, not stop at an unparsed top page.
    for expected in [
        "restore",
        "session-run",
        "host",
        "host request-restore",
        "mcp",
    ] {
        assert!(visited.contains(expected), "help walk missed {expected}");
    }
    assert!(
        missing.is_empty(),
        "docs/user/cli.md is missing: {missing:#?}"
    );
}
