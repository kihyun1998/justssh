//! The host key file, read or made as acwbroker's `hostkey.FileStore` does: an OpenSSH private
//! key file, ed25519 with the comment `acwbroker` when this side writes it.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use justssh::Zeroizing;
use justssh_keys::KeyFile;

/// The ACRA home: `ACRA_HOME`, or else `.acrapoint` in the user's home directory.
pub fn acra_home() -> Option<PathBuf> {
    match std::env::var_os("ACRA_HOME").filter(|v| !v.is_empty()) {
        Some(home) => Some(PathBuf::from(home)),
        None => {
            let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
            let user = std::env::var_os(var).filter(|v| !v.is_empty())?;
            Some(PathBuf::from(user).join(".acrapoint"))
        }
    }
}

/// `<ACRA home>/.store/acwbroker/hostkey`.
pub fn default_path() -> Option<PathBuf> {
    Some(
        acra_home()?
            .join(".store")
            .join("acwbroker")
            .join("hostkey"),
    )
}

/// The key at `path`, made there first when there is no file.
pub fn load(path: &Path) -> Result<KeyFile, String> {
    match fs::read(path) {
        Ok(text) => read(path, &text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => generate(path),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

fn read(path: &Path, text: &[u8]) -> Result<KeyFile, String> {
    KeyFile::read(text, None)
        .map_err(|e| format!("{} is not a usable private key: {e}", path.display()))
}

/// Writes a new key under a name of its own beside `path`, then links it to `path`; the key
/// already there when the link finds one.
fn generate(path: &Path) -> Result<KeyFile, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|e| format!("generating: {e}"))?;
    let key = KeyFile::ed25519(seed).with_comment("acwbroker");
    let dir = path.parent().unwrap_or(Path::new("."));
    create_dir(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let (tmp, mut file) = staging(dir).map_err(|e| format!("staging: {e}"))?;
    let written = file
        .write_all(key.to_openssh().as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    let linked = written.and_then(|()| fs::hard_link(&tmp, path));
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(key),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let text = fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            read(path, &text)
        }
        Err(e) => Err(format!("publishing {}: {e}", path.display())),
    }
}

#[cfg(unix)]
fn create_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

/// A new file `hostkey-<random>.tmp` in `dir`, readable by its owner alone where that is a
/// file mode.
fn staging(dir: &Path) -> io::Result<(PathBuf, fs::File)> {
    loop {
        let mut name = [0u8; 8];
        getrandom::fill(&mut name).map_err(io::Error::other)?;
        let hex: String = name.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = dir.join(format!("hostkey-{hex}.tmp"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
}
