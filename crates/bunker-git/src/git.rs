use crate::Limits;
use anyhow::{bail, ensure, Context, Result};
use std::{
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn regular_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "repository paths must be absolute");
    let mut part = PathBuf::new();
    for c in path.components() {
        ensure!(
            !matches!(c, Component::ParentDir | Component::CurDir),
            "noncanonical path"
        );
        part.push(c);
        let m = fs::symlink_metadata(&part).context("inaccessible repository path")?;
        ensure!(
            !m.file_type().is_symlink(),
            "symlink repository path refused"
        );
    }
    Ok(())
}

pub(crate) fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    regular_path(path)?;
    let m = fs::metadata(path)?;
    ensure!(
        m.is_file() && m.len() <= cap as u64,
        "nonregular or oversized metadata"
    );
    let mut out = Vec::new();
    fs::File::open(path)?
        .take((cap as u64).saturating_add(1))
        .read_to_end(&mut out)?;
    ensure!(out.len() <= cap, "metadata exceeds size cap");
    Ok(out)
}

pub(crate) fn optional(path: &Path, cap: usize) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(read(path, cap)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub(crate) struct Git<'a> {
    pub exe: &'a Path,
    pub dir: &'a Path,
    pub limits: &'a Limits,
    pub alternate: Option<&'a Path>,
}
impl Git<'_> {
    pub fn run(&self, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        let mut command = Command::new(self.exe);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.dir)
            .env("XDG_CONFIG_HOME", self.dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_ALLOW_PROTOCOL", "")
            .env("LC_ALL", "C")
            .env("GIT_COMMITTER_NAME", "Bunker")
            .env("GIT_COMMITTER_EMAIL", "restore@bunker.invalid")
            .env("GIT_COMMITTER_DATE", "@1 +0000")
            .arg("--no-pager")
            .arg("--git-dir")
            .arg(self.dir)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.logAllRefUpdates=false",
                "-c",
                "gc.auto=0",
                "-c",
                "core.fsync=loose-object,reference",
                "-c",
                "core.commitGraph=false",
                "-c",
                "maintenance.auto=false",
                "-c",
                "protocol.allow=never",
                "-c",
                "core.useReplaceRefs=false",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(path) = self.alternate {
            let p = path.to_str().context("non-UTF-8 object directory")?;
            ensure!(
                !p.contains([':', '\n', '\r', '"']),
                "unsupported object-directory path"
            );
            command.env("GIT_ALTERNATE_OBJECT_DIRECTORIES", p);
        }
        let mut child = command
            .spawn()
            .context("Git unavailable or could not start")?;
        let mut stdin = child.stdin.take().context("Git stdin missing")?;
        let bytes = input.to_vec();
        let writer = thread::spawn(move || stdin.write_all(&bytes));
        let mut stdout = child.stdout.take().context("Git stdout missing")?;
        let cap = self.limits.max_command_bytes;
        let reader = thread::spawn(move || {
            let mut out = Vec::new();
            stdout
                .by_ref()
                .take((cap as u64).saturating_add(1))
                .read_to_end(&mut out)?;
            Ok::<_, std::io::Error>(out)
        });
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() >= Duration::from_secs(self.limits.command_timeout_secs) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                let _ = reader.join();
                bail!("Git command exceeded deadline");
            }
            thread::sleep(Duration::from_millis(5));
        };
        let written = writer
            .join()
            .map_err(|_| anyhow::anyhow!("Git writer failed"))?;
        let out = reader
            .join()
            .map_err(|_| anyhow::anyhow!("Git reader failed"))??;
        ensure!(out.len() <= cap, "Git command output exceeds size cap");
        ensure!(
            status.success(),
            "Git plumbing failed (diagnostic content suppressed)"
        );
        written?;
        Ok(out)
    }
    pub fn text(&self, args: &[&str], input: &[u8]) -> Result<String> {
        String::from_utf8(self.run(args, input)?).context("unsupported non-UTF-8 Git metadata")
    }
}
