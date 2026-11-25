//! Small file helpers: private files written atomically.

use std::io::Write;
use std::path::Path;

use crate::FedError;

/// Write `bytes` to `path` through a temporary file and a rename, readable
/// by the owner only on Unix (Windows inherits the data directory's ACL).
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), FedError> {
    let dir = path
        .parent()
        .ok_or_else(|| FedError::Invalid(format!("{} has no parent folder", path.display())))?;
    std::fs::create_dir_all(dir)
        .map_err(FedError::io(format!("cannot create {}", dir.display())))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.tmp"));
    let write = || -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        sync_dir(dir);
        Ok(())
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        FedError::Io(format!("cannot write {}", path.display()), e)
    })
}

/// Best-effort: make a rename in `dir` durable (Unix only; NTFS journals
/// renames itself).
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Read a file, `None` if it does not exist.
pub(crate) fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, FedError> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(FedError::Io(format!("cannot read {}", path.display()), e)),
    }
}
