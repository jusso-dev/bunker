//! Disposable CLI fixtures for daemon logging and the local status socket.
use std::{fs, path::PathBuf, process::Command};

const PASSPHRASE: &str = "daemon-cli-fixture";

struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    work: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = root.join("repo");
        bunker::repository::Repository::init(&repo, PASSPHRASE).unwrap();
        let work = root.join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("file"), "fixture").unwrap();
        Self {
            _temp: temp,
            repo,
            work,
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bunker"));
        command
            .arg("--repo")
            .arg(&self.repo)
            .env("BUNKER_PASSPHRASE", PASSPHRASE)
            .env_remove("BUNKER_LOG");
        command
    }
    fn daemon_once(&self, configure: impl FnOnce(&mut Command)) -> std::process::Output {
        let mut command = self.command();
        configure(&mut command);
        command
            .args(["daemon", "--once", "--workspace"])
            .arg(&self.work)
            .output()
            .unwrap()
    }
}
fn log_lines(stderr: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(|line| serde_json::from_str(line).expect("every stderr line is a JSON log record"))
        .collect()
}
fn levels(lines: &[serde_json::Value]) -> Vec<&str> {
    lines.iter().map(|l| l["level"].as_str().unwrap()).collect()
}

#[test]
fn log_level_flag_and_env_filter_structured_lines() {
    let f = Fixture::new();
    let default = f.daemon_once(|_| {});
    assert!(default.status.success());
    let lines = log_lines(&default.stderr);
    assert!(lines.iter().all(|l| l["message"].is_string()));
    assert!(lines.iter().any(|l| l["event"] == "daemon_started"));
    assert!(!levels(&lines).contains(&"debug"));

    let debug = f.daemon_once(|c| {
        c.args(["--log-level", "debug"]);
    });
    assert!(debug.status.success());
    let lines = log_lines(&debug.stderr);
    assert!(lines
        .iter()
        .any(|l| l["level"] == "debug" && l["event"] == "scheduler_tick"));

    let env_debug = f.daemon_once(|c| {
        c.env("BUNKER_LOG", "debug");
    });
    assert!(levels(&log_lines(&env_debug.stderr)).contains(&"debug"));

    // The flag overrides the environment.
    let quiet = f.daemon_once(|c| {
        c.env("BUNKER_LOG", "debug").args(["--log-level", "warn"]);
    });
    assert!(quiet.status.success());
    let lines = log_lines(&quiet.stderr);
    assert!(lines
        .iter()
        .all(|l| l["level"] == "warn" || l["level"] == "error"));
}

#[test]
fn invalid_log_levels_are_rejected_clearly() {
    let f = Fixture::new();
    let flag = f.daemon_once(|c| {
        c.args(["--log-level", "loud"]);
    });
    assert!(!flag.status.success());
    let stderr = String::from_utf8_lossy(&flag.stderr);
    assert!(stderr.contains("invalid log level"), "{stderr}");
    assert!(stderr.contains("error, warn, info or debug"), "{stderr}");

    let env = f.daemon_once(|c| {
        c.env("BUNKER_LOG", "loud");
    });
    assert_eq!(env.status.code(), Some(1));
    let lines = log_lines(&env.stderr);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["level"], "error");
    let message = lines[0]["message"].as_str().unwrap();
    assert!(message.starts_with("BUNKER_LOG: invalid log level"), "{message}");
    assert!(
        !f.repo.join("schedule.json").exists(),
        "rejected configuration still ran the scheduler"
    );
}

#[cfg(unix)]
#[test]
fn running_daemon_answers_status_and_stops_cleanly() {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    let f = Fixture::new();
    let mut child = f
        .command()
        .args(["daemon", "--workspace"])
        .arg(&f.work)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut status = None;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if f.repo.join("daemon.sock").exists() {
            let output = f.command().arg("status").output().unwrap();
            if output.status.success() {
                let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                if value["state"]["last_snapshot"].is_string() {
                    status = Some(value);
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let Some(status) = status else {
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        panic!(
            "daemon status unavailable: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    assert_eq!(status["running"], true);
    assert_eq!(status["mode"], "standalone");
    assert_eq!(
        status["state"]["workspace"],
        f.work.to_str().unwrap(),
        "status reports the running daemon's schedule"
    );
    // A second scheduler for the same repository is refused while the first runs.
    let second = f
        .command()
        .args(["daemon", "--once", "--workspace"])
        .arg(&f.work)
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("daemon already running"));

    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let deadline = Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(exit) = child.try_wait().unwrap() {
            break exit;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("daemon ignored SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(exit.success(), "daemon did not exit cleanly: {exit:?}");
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(log_lines(stderr.as_bytes())
        .iter()
        .any(|l| l["event"] == "daemon_stopped"));
    assert!(!f.repo.join("daemon.sock").exists());
    let after = f.command().arg("status").output().unwrap();
    assert!(!after.status.success());
    assert!(String::from_utf8_lossy(&after.stderr).contains("daemon is not running"));
}
