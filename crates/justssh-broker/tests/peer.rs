//! What this machine reports, measured against itself (acwbroker
//! `infrastructure/peer/peer_windows_test.go`). Windows only; macOS is `peer_macos.rs`.
#![cfg(windows)]

use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

use justssh_broker::peer;
use justssh_broker::tokens::Hold;

#[test]
fn the_owner_of_a_connection_is_the_process_that_opened_it() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let listener = TcpListener::bind(bind).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, remote) = listener.accept().unwrap();
        assert_eq!(remote, client.local_addr().unwrap());

        let c = peer::probe(remote);
        assert_eq!(c.error, None, "{bind}");
        assert_eq!(c.pid, std::process::id(), "{bind}");
        let exe = std::env::current_exe().unwrap();
        assert!(
            c.image_path.eq_ignore_ascii_case(exe.to_str().unwrap()),
            "{} is not {}",
            c.image_path,
            exe.display()
        );
        assert_eq!(c.session, peer::own_session().unwrap(), "{bind}");
        assert!(c.session.is_some());
        assert_eq!(c.user, peer::own_user(), "{bind}");
        assert!(c.user.as_deref().is_some_and(|s| s.starts_with("S-1-")));
        assert_eq!(c.ancestry.first(), Some(&std::process::id()));
        assert_eq!(c.ancestry.get(1).copied(), peer::parent());
        assert_eq!(c.lineage.len(), c.ancestry.len());
        assert!(c.lineage[0].created.is_some());
    }
}

#[test]
fn an_endpoint_nothing_owns_is_reported_as_unmeasured() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let c = peer::probe(addr);
    assert!(c.unowned(), "{c:?}");
}

#[test]
fn a_held_process_reports_its_exit_and_a_hold_on_nothing_fails() {
    let mut child = Command::new("cmd")
        .args(["/c", "ping -n 2 127.0.0.1 >nul"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let held = peer::Holder::default().hold(child.id()).unwrap();
    child.wait().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let seen = tokio::time::timeout(Duration::from_secs(5), held.exited())
            .await
            .expect("the exit was never reported");
        assert!(seen, "the watch ended without seeing the exit");
    });
    assert!(peer::Holder::default().hold(0).is_err());
}

#[test]
fn an_executables_version_resource_is_read() {
    let m = peer::metadata(r"C:\Windows\System32\notepad.exe").unwrap();
    assert!(m.company.contains("Microsoft"), "{m:?}");
    assert!(
        m.original_filename
            .to_ascii_lowercase()
            .starts_with("notepad.exe"),
        "{m:?}"
    );
    assert!(peer::metadata(r"C:\no\such\file.exe").is_err());
}
