//! The host key files, read or made as acwbroker's `hostkey.FileStore` does: OpenSSH private key
//! files, `hostkey` ed25519 and `hostkey-rsa` RSA-2048 when this side writes them, with the
//! comment `acwbroker`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use justssh::{HostKey, ServerConfig, ServerConfigBuilder, Zeroizing};
use justssh_keys::KeyFile;

use crate::log::Log;

/// The host keys a connection is served with: the primary key, and the RSA key at a path,
/// offered as `ssh-rsa` alone after it and read or made on each connection.
#[derive(Clone)]
pub struct HostKeys {
    primary: HostKey,
    legacy: Option<PathBuf>,
}

impl HostKeys {
    pub fn new(primary: HostKey) -> Self {
        HostKeys {
            primary,
            legacy: None,
        }
    }

    /// The RSA key at `path`.
    pub fn legacy(mut self, path: PathBuf) -> Self {
        self.legacy = Some(path);
        self
    }

    /// The server's configuration with these keys; without the RSA key, and the reason logged,
    /// when it cannot be had.
    pub(crate) async fn config(&self, log: &Log) -> ServerConfigBuilder {
        let config = ServerConfig::builder(self.primary.clone());
        let Some(path) = self.legacy.clone() else {
            return config;
        };
        let file = match tokio::task::spawn_blocking(move || load_rsa(&path)).await {
            Ok(Ok(file)) => file,
            Ok(Err(e)) => {
                log.error(format!("legacy host key unavailable: hostkey: {e}"), &[]);
                return config;
            }
            Err(e) => {
                log.error(format!("legacy host key unavailable: {e}"), &[]);
                return config;
            }
        };
        match HostKey::new(file.private_key().clone()).with_algorithms(&["ssh-rsa"]) {
            Ok(key) => config.host_key(key),
            Err(e) => {
                log.error(format!("legacy host key unusable: {e}"), &[]);
                config
            }
        }
    }
}

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

/// `hostkey-rsa` beside the key at `primary`.
pub fn legacy_path(primary: &Path) -> PathBuf {
    primary.with_file_name("hostkey-rsa")
}

/// The key at `path`, an ed25519 key made there first when there is no file.
pub fn load(path: &Path) -> Result<KeyFile, String> {
    load_or(path, ed25519)
}

/// The key at `path`, an RSA-2048 key made there first when there is no file.
pub fn load_rsa(path: &Path) -> Result<KeyFile, String> {
    load_or(path, rsa)
}

fn load_or(path: &Path, make: fn() -> Result<KeyFile, String>) -> Result<KeyFile, String> {
    match fs::read(path) {
        Ok(text) => read(path, &text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => generate(path, make),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

fn ed25519() -> Result<KeyFile, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|e| format!("generating: {e}"))?;
    Ok(KeyFile::ed25519(seed))
}

fn rsa() -> Result<KeyFile, String> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| format!("generating: {e}"))?;
    let [p, q] = key.primes() else {
        return Err("generating: not two primes".to_owned());
    };
    let secret = |n: &rsa::BigUint| Zeroizing::new(n.to_bytes_be());
    KeyFile::rsa(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
        secret(key.d()),
        secret(p),
        secret(q),
    )
    .map_err(|e| format!("generating: {e}"))
}

/// The operating system's random numbers, for the `rand_core` generation rsa 0.9 takes.
struct OsRng;

impl rsa_rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("the operating system's random numbers");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa_rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa_rand_core::CryptoRng for OsRng {}

fn read(path: &Path, text: &[u8]) -> Result<KeyFile, String> {
    KeyFile::read(text, None)
        .map_err(|e| format!("{} is not a usable private key: {e}", path.display()))
}

/// Writes a new key from `make` under a name of its own beside `path`, then links it to `path`;
/// the key already there when the link finds one.
fn generate(path: &Path, make: fn() -> Result<KeyFile, String>) -> Result<KeyFile, String> {
    let key = make()?.with_comment("acwbroker");
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
