//! What this machine reports, measured against itself (acwbroker
//! `infrastructure/peer/peer_darwin_test.go`, `table_darwin_test.go`, `hold_darwin_test.go`).
//! macOS only.
#![cfg(target_os = "macos")]

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use justssh_broker::caller::ProcessTable;
use justssh_broker::peer;
use justssh_broker::tokens::Hold;

/// Longer than the hold's poll, so a wait that expects nothing can tell "never" from "not yet".
const QUIET: Duration = Duration::from_millis(1500);

/// A connection to a listener on `bind` opened by another process, and that process.
fn accept_from(bind: &str) -> Option<(TcpStream, Child)> {
    let listener = TcpListener::bind(bind).ok()?;
    let addr = listener.local_addr().unwrap();
    let host = match addr {
        SocketAddr::V4(a) => a.ip().to_string(),
        SocketAddr::V6(a) => a.ip().to_string(),
    };
    let script = format!("exec 3<>/dev/tcp/{host}/{}; sleep 20", addr.port());
    let child = Command::new("/bin/bash")
        .args(["-c", &script])
        .spawn()
        .unwrap();
    let (conn, _) = listener.accept().unwrap();
    Some((conn, child))
}

fn kill(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn the_owner_of_a_loopback_connection_is_the_process_that_opened_it() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let Some((conn, child)) = accept_from(bind) else {
            eprintln!("skipped {bind}: cannot listen");
            continue;
        };
        let owner = peer::owner(conn.peer_addr().unwrap());
        let pid = child.id();
        kill(child);
        assert_eq!(owner.error, None, "{bind}");
        assert_eq!(owner.pid, pid, "{bind}");
        assert!(!owner.image_path.is_empty(), "{bind}");
    }
}

#[test]
fn an_unowned_port_is_a_failed_measurement_and_not_pid_zero() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let owner = peer::owner(addr);
    let error = owner.error.unwrap_or_default();
    assert!(error.contains("no socket owns that endpoint"), "{error}");
    assert_eq!(owner.pid, 0);
}

#[test]
fn the_address_is_compared_and_not_only_the_port() {
    let Some((conn, child)) = accept_from("127.0.0.1:0") else {
        return;
    };
    let mut other = conn.peer_addr().unwrap();
    other.set_ip("127.0.0.2".parse().unwrap());
    let owner = peer::owner(other);
    kill(child);
    let error = owner.error.unwrap_or_default();
    assert!(
        error.contains("no socket owns that endpoint"),
        "pid {} {error}",
        owner.pid
    );
}

#[test]
fn the_scan_costs_far_less_than_a_dial() {
    let Some((conn, child)) = accept_from("127.0.0.1:0") else {
        return;
    };
    let start = Instant::now();
    let owner = peer::owner(conn.peer_addr().unwrap());
    let took = start.elapsed();
    kill(child);
    assert_eq!(owner.error, None);
    assert!(
        took < Duration::from_millis(100),
        "the lookup took {took:?}"
    );
}

#[test]
fn the_snapshot_agrees_with_the_kernel_about_this_process() {
    let t = peer::table().unwrap();
    let me = std::process::id();
    let p = t.info(me).unwrap();
    assert_eq!(p.pid, me);
    assert_eq!(Some(p.parent), peer::parent());
    assert!(!p.name.is_empty());
    let created = p
        .created
        .expect("a start time from the same copy as the pid");
    let age = SystemTime::now().duration_since(created).unwrap();
    assert!(age < Duration::from_secs(3600), "{age:?}");
}

#[test]
fn an_absent_process_is_an_error_and_not_a_zero_value() {
    assert!(peer::table().unwrap().info(99_999_999).is_err());
}

fn sleeper() -> Child {
    Command::new("/bin/sleep").arg("30").spawn().unwrap()
}

#[test]
fn the_snapshot_does_not_change_after_a_process_exits() {
    let child = sleeper();
    let pid = child.id();
    let t = peer::table().unwrap();
    assert!(t.info(pid).is_ok());
    kill(child);
    assert!(
        t.info(pid).is_ok(),
        "the snapshot lost a process that exited after it"
    );
}

#[test]
fn created_is_accurate_to_better_than_a_second() {
    let before = SystemTime::now();
    let child = sleeper();
    let after = SystemTime::now();
    let created = peer::table().unwrap().info(child.id()).unwrap().created;
    kill(child);
    let created = created.unwrap();
    let slack = Duration::from_millis(50);
    assert!(
        created + slack >= before && created <= after + slack,
        "{created:?} not within [{before:?}, {after:?}]"
    );
}

#[test]
fn a_child_points_at_us_as_its_parent() {
    let child = sleeper();
    let parent = peer::table().unwrap().info(child.id()).unwrap().parent;
    kill(child);
    assert_eq!(parent, std::process::id());
}

/// `pid`'s controlling terminal read past this code: `ps` names it, `stat` gives its number.
fn kernel_tty(pid: u32) -> Option<i32> {
    let out = Command::new("/bin/ps")
        .args(["-o", "tty=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let name = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    if name.is_empty() || name == "??" {
        return None;
    }
    let out = Command::new("/usr/bin/stat")
        .args(["-f", "%r", &format!("/dev/{name}")])
        .output()
        .unwrap();
    Some(
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap(),
    )
}

/// `script(1)` running `sleep 5` on a new pty, and the pid of that `sleep` once it has one.
fn in_a_terminal() -> (Child, u32) {
    let mut script = Command::new("/usr/bin/script")
        .args(["-q", "/dev/null", "/bin/sleep", "5"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let out = Command::new("/usr/bin/pgrep")
            .args(["-P", &script.id().to_string()])
            .output()
            .unwrap();
        if let Some(pid) = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .find_map(|l| l.trim().parse::<u32>().ok())
            && kernel_tty(pid).is_some()
        {
            return (script, pid);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = script.kill();
    let _ = script.wait();
    panic!("script(1) started no child with a terminal within 2s");
}

#[test]
fn the_controlling_terminal_agrees_with_the_kernel() {
    let (script, child) = in_a_terminal();
    let tty = kernel_tty(child).unwrap();
    let holders = peer::terminal_holders(tty).unwrap();
    let me = peer::terminal_holders(kernel_tty(std::process::id()).unwrap_or(-2)).unwrap();
    kill(script);
    assert!(holders.iter().any(|h| h.pid == child), "{holders:?}");
    assert!(me.iter().all(|h| h.pid != child), "{me:?}");
}

#[test]
fn the_holders_of_a_terminal_are_the_processes_whose_controlling_terminal_it_is() {
    let (script, child) = in_a_terminal();
    let tty = kernel_tty(child).unwrap();
    let created = peer::table().unwrap().info(child).unwrap().created;
    let holders = peer::terminal_holders(tty).unwrap();
    for h in &holders {
        assert_eq!(kernel_tty(h.pid), Some(tty), "pid {} was reported", h.pid);
    }
    kill(script);
    assert!(
        holders
            .iter()
            .any(|h| h.pid == child && h.created == created),
        "{holders:?} lacks {child} with its start time"
    );
    assert_eq!(peer::terminal_holders(i32::MAX - 7), Ok(Vec::new()));
}

/// A process whose parent is not this test, as every real caller's is not.
fn orphan() -> u32 {
    let out = Command::new("/bin/bash")
        .args(["-c", "sleep 60 >/dev/null 2>&1 & echo $!"])
        .output()
        .unwrap();
    let pid: u32 = String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let ppid = Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let mut s = String::new();
    ppid.stdout.as_slice().read_to_string(&mut s).unwrap();
    assert_eq!(s.trim(), "1", "orphan {pid} is this test's own child");
    pid
}

fn sigkill(pid: u32) {
    let ok = Command::new("/bin/kill")
        .args(["-9", &pid.to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok, "kill {pid}");
}

/// Whether `held` reports an exit within `wait`, read on a runtime of its own.
fn reports_exit(held: justssh_broker::tokens::Held, wait: Duration) -> bool {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        tokio::time::timeout(wait, held.exited())
            .await
            .unwrap_or(false)
    })
}

#[test]
fn a_held_process_that_exits_is_reported() {
    let pid = orphan();
    let held = peer::Holder::default().hold(pid).unwrap();
    std::thread::sleep(QUIET);
    sigkill(pid);
    assert!(reports_exit(held, Duration::from_secs(5)));
}

#[test]
fn a_held_process_that_runs_on_is_not_reported() {
    let pid = orphan();
    let held = peer::Holder::default().hold(pid).unwrap();
    let reported = reports_exit(held, QUIET);
    sigkill(pid);
    assert!(!reported, "an exit was reported while {pid} ran");
}

#[test]
fn holding_a_process_that_is_already_gone_is_an_error() {
    let pid = orphan();
    drop(peer::Holder::default().hold(pid).unwrap());
    sigkill(pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .status()
        .unwrap()
        .success()
    {
        assert!(
            Instant::now() < deadline,
            "{pid} still exists 5s after SIGKILL"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(peer::Holder::default().hold(pid).is_err());
}
