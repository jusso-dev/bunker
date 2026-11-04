//! Publication for ACL-protected state, separate from ordinary repository writes.
use anyhow::Result;
use cap_std::fs::Dir;

pub(crate) fn atomic_write(dir: &Dir, path: &str, bytes: &[u8], replace: bool) -> Result<()> {
    #[cfg(not(windows))]
    return crate::repository::atomic_write(dir, path, bytes, replace);
    #[cfg(windows)]
    {
        use anyhow::{bail, ensure};
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use std::{io::Write, path::Path};
        crate::repository::safe_path(path)?;
        ensure!(
            Path::new(path).components().count() == 1,
            "expected a state filename"
        );
        if !replace && dir.try_exists(path)? {
            bail!("destination already exists");
        }
        let temp = format!(".bunker-{}.tmp", hex::encode(crate::crypto::random::<16>()));
        let result = (|| -> Result<()> {
            let mut options = cap_std::fs::OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            let mut file = dir.open_with(&temp, &options)?.into_std();
            // No secret bytes may reach an object whose inherited DACL is unsafe.
            crate::win_acl::check_file(&file)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if replace {
                dir.rename(&temp, dir, path)?;
            } else {
                dir.hard_link(&temp, dir, path)?;
                dir.remove_file(&temp)?;
            }
            crate::repository::sync_dir(dir, Path::new("."))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = dir.remove_file(&temp);
        }
        result
    }
}
