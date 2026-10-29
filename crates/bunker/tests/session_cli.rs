#![cfg(unix)]
use std::{
    fs,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    bunker::repository::Repository::init(&repo, "session-cli-fixture").unwrap();
    (temp, repo)
}
fn wrapper(repo: &std::path::Path, home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bunker"));
    command
        .arg("--repo")
        .arg(repo)
        .args(["session-run", "--agent", "codex", "--home"])
        .arg(home)
        .arg("--")
        .env("BUNKER_PASSPHRASE", "session-cli-fixture");
    command
}
#[test]
fn failed_capture_preserves_failed_child_but_fails_successful_child() {
    for (child, expected) in [(7, 7), (0, 1)] {
        let (temp, repo) = fixture();
        let output = wrapper(&repo, &temp.path().join("missing-home"))
            .args(["/bin/sh", "-c", &format!("exit {child}")])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected));
        assert!(String::from_utf8_lossy(&output.stderr).contains("Session backup failed"));
    }
}
#[test]
fn failed_capture_preserves_cancellation_status() {
    let (temp, repo) = fixture();
    let ready = temp.path().join("ready");
    let mut child = wrapper(&repo, &temp.path().join("missing-home"))
        .args([
            "/bin/sh",
            "-c",
            "printf ready > \"$1\"; exec /bin/sleep 20",
            "fixture",
        ])
        .arg(&ready)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("fixture child did not start");
    }
    assert_eq!(fs::read(&ready).unwrap(), b"ready");
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(130));
    assert!(String::from_utf8_lossy(&result.stderr).contains("Session backup failed"));
}
