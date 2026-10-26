//! The host keys the broker serves: the ed25519 key, and beside it the RSA key `hostkey-rsa`
//! offered only as `ssh-rsa`, read or made on a connection as acwbroker's `serverConfig` has it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use justssh::{Client, ClientConfig, HostKey, InfoRequest, Zeroizing};
use justssh_broker::broker;
use justssh_broker::caller::Caller;
use justssh_broker::hostkey::{self, HostKeys};
use justssh_broker::log::Log;
use justssh_broker::tokens::{Config, Tokens};
use justssh_keys::KeyFile;
use justssh_tokio::{ClientHandler, Connected, Deadlines};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);

/// Takes note of the host key and goes no further.
#[derive(Default)]
struct Note(Option<Vec<u8>>);

impl ClientHandler for Note {
    async fn check_host_key(&mut self, key: &[u8]) -> bool {
        self.0 = Some(key.to_vec());
        false
    }

    async fn answer(&mut self, _request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        Vec::new()
    }
}

/// A broker whose legacy key is at `legacy`; its address.
async fn broker(legacy: PathBuf, log: Log) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let host_keys =
        HostKeys::new(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).legacy(legacy);
    let tokens = Tokens::new(Config::default(), tokio::runtime::Handle::current());
    tokio::spawn(broker::serve(
        listener,
        host_keys,
        tokens,
        Duration::from_secs(15),
        Arc::new(|_, _| Caller::new(4242)),
        log,
    ));
    addr
}

/// The host key a client offering only `algorithms` is shown, or none.
async fn shown(addr: &str, algorithms: &[&str]) -> Option<Vec<u8>> {
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut client = Client::new(
        ClientConfig::builder(b"u")
            .host_key_algorithms(algorithms)
            .build(),
    );
    let mut note = Note::default();
    let connected = timeout(
        LIMIT,
        justssh_tokio::connect(stream, &mut client, &Deadlines::new(), &[], &mut note),
    )
    .await
    .unwrap();
    assert!(!matches!(connected, Ok(Connected::Authenticated { .. })));
    note.0
}

/// The blob of an `authorized_keys` line.
fn blob(line: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(line).unwrap();
    let b64 = text.split_whitespace().nth(1).unwrap();
    base64(b64)
}

fn base64(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|&c| c != b'=') {
        acc = acc << 6 | A.iter().position(|&a| a == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "justssh-broker-hostkey-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/hostkey")
        .join(name)
}

#[tokio::test]
async fn the_rsa_key_go_wrote_is_offered_as_ssh_rsa_alone() {
    let dir = scratch("go");
    let path = hostkey::legacy_path(&dir.join("hostkey"));
    assert_eq!(path, dir.join("hostkey-rsa"));
    std::fs::copy(fixture("hostkey-rsa"), &path).unwrap();
    let addr = broker(path, Log::discard()).await;

    let want = blob(&std::fs::read(fixture("hostkey-rsa.pub")).unwrap());
    assert_eq!(shown(&addr, &["ssh-rsa"]).await, Some(want));
    assert_eq!(shown(&addr, &["rsa-sha2-256", "rsa-sha2-512"]).await, None);
    let ed25519 = shown(&addr, &["ssh-ed25519"]).await.unwrap();
    assert_eq!(&ed25519[4..15], b"ssh-ed25519");
}

#[tokio::test]
async fn a_missing_rsa_key_is_made_on_a_connection_and_kept() {
    let dir = scratch("made");
    let path = dir.join("hostkey-rsa");
    let addr = broker(path.clone(), Log::discard()).await;
    assert!(!path.exists());

    let first = shown(&addr, &["ssh-rsa"]).await.unwrap();
    let file = KeyFile::read(&std::fs::read(&path).unwrap(), None).unwrap();
    assert_eq!(file.comment(), b"acwbroker");
    assert_eq!(file.private_key().plain_public_blob(), first);
    // e = 65537 and a 2048-bit modulus: 4+7, 4+3, 4+1+256.
    assert_eq!(first.len(), 11 + 7 + 261);
    assert_eq!(shown(&addr, &["ssh-rsa"]).await.unwrap(), first);
}

#[tokio::test]
async fn without_an_rsa_key_the_ed25519_key_is_served_and_the_reason_logged() {
    let dir = scratch("bad");
    let path = dir.join("hostkey-rsa");
    std::fs::write(&path, b"not a key").unwrap();
    let lines = Lines::default();
    let addr = broker(path, Log::new(lines.clone(), None)).await;

    assert!(shown(&addr, &["ssh-ed25519"]).await.is_some());
    assert_eq!(shown(&addr, &["ssh-rsa"]).await, None);
    let text = lines.text();
    assert!(
        text.contains("level=ERROR msg=\"legacy host key unavailable: hostkey: "),
        "{text}"
    );
}

#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Lines {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Lines {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

#[test]
fn first_connections_at_once_all_get_the_one_key_published() {
    let dir = scratch("race");
    let path = dir.join("hostkey-rsa");
    let made: Vec<Vec<u8>> = std::thread::scope(|s| {
        let racers: Vec<_> = (0..8)
            .map(|_| s.spawn(|| hostkey::load_rsa(&path).unwrap()))
            .collect();
        racers
            .into_iter()
            .map(|r| r.join().unwrap().private_key().plain_public_blob())
            .collect()
    });
    let on_disk = KeyFile::read(&std::fs::read(&path).unwrap(), None)
        .unwrap()
        .private_key()
        .plain_public_blob();
    assert!(made.iter().all(|k| *k == on_disk));
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(left.len(), 1);
}
