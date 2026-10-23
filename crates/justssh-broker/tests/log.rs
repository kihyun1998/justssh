//! The broker's log: lines as Go's `log/slog` text handler writes them, and the shared,
//! rotating file (acwbroker `cmd/acwbroker/logging.go`, `infrastructure/logfile`). The golden
//! lines were printed by Go 1.26.3's slog from the same inputs.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use justssh_broker::log::{Level, Log, Value, go_duration, line, quote, rfc3339_millis};
use justssh_broker::logfile::{LogFile, Tee};

/// 2026-10-23T07:09:00.123456789Z.
fn at() -> SystemTime {
    UNIX_EPOCH + Duration::new(1_792_739_340, 123_456_789)
}

const KST: i32 = 9 * 60;

fn text(level: Level, msg: &[u8], attrs: &[(&str, Value)]) -> String {
    let mut all = vec![("profile", Value::from("prod A"))];
    all.extend(attrs.iter().cloned());
    String::from_utf8(line(at(), KST, level, msg, &all)).unwrap()
}

#[test]
fn lines_are_what_slog_writes() {
    let cases: Vec<(String, &str)> = vec![
        (
            text(
                Level::Info,
                br"authenticated: listener=127.0.0.1:51230 caller=pid=4242 image=C:\x\putty.exe session=1 user=S-1-5-21-1 chain=4242(putty.exe)<-100 stop=no-parent verdict=in-tree admitted=claim live=1",
                &[],
            ),
            r#"time=2026-10-23T16:09:00.123+09:00 level=INFO msg="authenticated: listener=127.0.0.1:51230 caller=pid=4242 image=C:\\x\\putty.exe session=1 user=S-1-5-21-1 chain=4242(putty.exe)<-100 stop=no-parent verdict=in-tree admitted=claim live=1" profile="prod A""#,
        ),
        (
            text(
                Level::Warn,
                format!(
                    "authentication failed: listener=127.0.0.1:1 caller=pid=? image=? (boom) verdict=unmeasured user={} reason=acwbroker: admission closed",
                    quote(b"a\"b\x80\tc\xe2\x80\x8b")
                )
                .as_bytes(),
                &[],
            ),
            r#"time=2026-10-23T16:09:00.123+09:00 level=WARN msg="authentication failed: listener=127.0.0.1:1 caller=pid=? image=? (boom) verdict=unmeasured user=\"a\\\"b\\x80\\tc\\u200b\" reason=acwbroker: admission closed" profile="prod A""#,
        ),
        (
            text(Level::Error, b"x=y", &[]),
            r#"time=2026-10-23T16:09:00.123+09:00 level=ERROR msg="x=y" profile="prod A""#,
        ),
        (
            text(
                Level::Info,
                b"credential disposed",
                &[("reason", "idle".into()), ("live", 0usize.into())],
            ),
            r#"time=2026-10-23T16:09:00.123+09:00 level=INFO msg="credential disposed" profile="prod A" reason=idle live=0"#,
        ),
        (
            text(
                Level::Info,
                b"plain",
                &[
                    ("err", "".into()),
                    ("k", r"a\b".into()),
                    ("u", "é".into()),
                    ("z", "\u{a0}".into()),
                    ("q", "x\"y".into()),
                    ("n", Value::Int(-3)),
                ],
            ),
            r#"time=2026-10-23T16:09:00.123+09:00 level=INFO msg=plain profile="prod A" err="" k=a\b u=é z="\u00a0" q="x\"y" n=-3"#,
        ),
        (
            text(Level::Info, b"req \xe2\x82", &[]),
            r#"time=2026-10-23T16:09:00.123+09:00 level=INFO msg="req \xe2\x82" profile="prod A""#,
        ),
    ];
    for (got, want) in cases {
        assert_eq!(got, format!("{want}\n"));
    }
    let utc = UNIX_EPOCH + Duration::from_secs(1_767_323_045);
    assert_eq!(
        String::from_utf8(line(utc, 0, Level::Info, b"utc", &[])).unwrap(),
        "time=2026-01-02T03:04:05.000Z level=INFO msg=utc\n"
    );
    let early = UNIX_EPOCH + Duration::from_millis(12_599_999);
    assert_eq!(
        rfc3339_millis(early, -(3 * 60 + 30)),
        "1969-12-31T23:59:59.999-03:30"
    );
}

#[test]
fn quote_is_gos_percent_q() {
    assert_eq!(
        quote(
            &[
                &b"a\"b\x80\tc"[..],
                "\u{200b}\u{1f600}\x7f\u{ad}".as_bytes()
            ]
            .concat()
        ),
        r#""a\"b\x80\tc\u200b😀\x7f\u00ad""#
    );
    assert_eq!(go_duration(Duration::from_secs(180)), "3m0s");
    assert_eq!(go_duration(Duration::from_secs(15)), "15s");
    assert_eq!(go_duration(Duration::from_secs(3605)), "1h0m5s");
}

#[test]
fn a_log_carries_its_profile_and_a_discarded_one_writes_nothing() {
    let out = Shared::default();
    let log = Log::clocked(out.clone(), Some("p".to_owned()), || (at(), 0));
    log.warn("w", &[("pid", 7u32.into())]);
    log.info("i", &[]);
    Log::discard().error("nothing", &[]);
    let none = Log::clocked(out.clone(), Some(String::new()), || (at(), 0));
    none.error("e", &[]);
    assert_eq!(
        out.text(),
        "time=2026-10-23T07:09:00.123Z level=WARN msg=w profile=p pid=7\n\
         time=2026-10-23T07:09:00.123Z level=INFO msg=i profile=p\n\
         time=2026-10-23T07:09:00.123Z level=ERROR msg=e\n"
    );
}

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("justssh-log-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir.join("acwbroker.log")
}

fn write(f: &mut LogFile, line: &str) {
    f.write_all(format!("{line}\n").as_bytes()).unwrap();
}

fn read(path: &std::path::Path) -> String {
    fs::read_to_string(path).unwrap()
}

fn numbered(path: &std::path::Path, n: u32) -> PathBuf {
    PathBuf::from(format!("{}.{n}", path.display()))
}

#[test]
fn it_appends_to_what_an_earlier_run_left() {
    let path = scratch("append");
    fs::write(&path, "earlier\n").unwrap();
    let mut f = LogFile::open(&path, 1 << 20, 3).unwrap();
    write(&mut f, "now");
    assert_eq!(read(&path), "earlier\nnow\n");
}

#[cfg(unix)]
#[test]
fn a_new_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = scratch("mode");
    let mut f = LogFile::open(&path, 1 << 20, 3).unwrap();
    write(&mut f, "x");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn it_rotates_at_the_limit_and_keeps_three_generations() {
    let path = scratch("rotate");
    let mut f = LogFile::open(&path, 10, 3).unwrap();
    for line in ["aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"] {
        write(&mut f, line);
    }
    assert_eq!(read(&path), "dddddddd\n");
    assert_eq!(read(&numbered(&path, 1)), "cccccccc\n");
    assert_eq!(read(&numbered(&path, 2)), "bbbbbbbb\n");
    assert!(!numbered(&path, 3).exists());
}

#[test]
fn with_one_generation_the_file_starts_over() {
    let path = scratch("keep1");
    let mut f = LogFile::open(&path, 10, 1).unwrap();
    write(&mut f, "aaaaaaaa");
    write(&mut f, "bbbbbbbb");
    assert_eq!(read(&path), "bbbbbbbb\n");
    assert!(!numbered(&path, 1).exists());
}

#[test]
fn a_line_is_never_split() {
    let path = scratch("split");
    let mut f = LogFile::open(&path, 10, 3).unwrap();
    let long = "x".repeat(25);
    write(&mut f, &long);
    assert_eq!(read(&path), format!("{long}\n"));
    assert!(!numbered(&path, 1).exists());
}

#[test]
fn another_writer_follows_the_rotation() {
    let path = scratch("follow");
    let mut a = LogFile::open(&path, 20, 3).unwrap();
    let mut b = LogFile::open(&path, 20, 3).unwrap();
    write(&mut a, "a1a1a1a1");
    write(&mut a, "a2a2a2a2a2a2a2");
    write(&mut b, "b1b1b1b1");
    assert!(read(&path).contains("b1b1b1b1"), "{}", read(&path));
    assert!(!read(&numbered(&path, 1)).contains("b1b1b1b1"));
}

#[test]
fn a_removed_file_is_recreated() {
    let path = scratch("removed");
    let mut f = LogFile::open(&path, 1 << 20, 3).unwrap();
    write(&mut f, "before");
    fs::remove_file(&path).unwrap();
    write(&mut f, "after");
    assert_eq!(read(&path), "after\n");
}

struct Failing(usize);

impl Write for Failing {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        self.0 += 1;
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn tee_keeps_writing_when_one_sink_fails() {
    let path = scratch("tee");
    let file = LogFile::open(&path, 1 << 20, 3).unwrap();
    let mut t = Tee::new(Failing(0), file);
    assert_eq!(t.write(b"line\n").unwrap(), 5);
    assert_eq!(t.first().0, 1);
    assert_eq!(read(&path), "line\n");
}
