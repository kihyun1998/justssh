//! Probe for #75, not for merging. One factual OS question: can a fresh socket bind the exact
//! local `addr:port` that an already-connected loopback socket holds? If the OS refuses, the
//! two sockets cannot share a local endpoint and the owner scan (first match by local
//! `addr:port`) cannot be led to the wrong process this way. If it allows the bind, the scan
//! returning its first match (code fact in `peer::owning_pid`) is what decides who is named.
#![cfg(any(windows, target_os = "macos"))]

use std::net::{TcpListener, TcpStream};

use socket2::{Domain, Socket, Type};

/// Reports, for each reuse option, whether a second socket could take the connected socket's
/// exact local endpoint. Printed with `--nocapture`; the test itself never fails.
#[test]
fn a_second_socket_taking_a_connected_endpoint() {
    // A real connected loopback pair, so the endpoint under test is one a process actually holds.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connected = TcpStream::connect(server_addr).unwrap();
    let (_accepted, _) = listener.accept().unwrap();
    let held = connected.local_addr().unwrap();
    eprintln!("PROBE held endpoint = {held}");

    for reuse_port in [false, true] {
        let s = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        // SO_REUSEADDR alone, then with SO_REUSEPORT where the platform has it.
        s.set_reuse_address(true).unwrap();
        #[cfg(unix)]
        if reuse_port {
            s.set_reuse_port(true).unwrap();
        }
        #[cfg(windows)]
        if reuse_port {
            eprintln!("PROBE reuse_port=skip (windows has no SO_REUSEPORT)");
            continue;
        }
        let r = s.bind(&held.into());
        eprintln!(
            "PROBE reuse_addr=true reuse_port={reuse_port} bind-to-held = {}",
            match &r {
                Ok(()) => "OK".to_owned(),
                Err(e) => format!("Err({})", e.kind()),
            }
        );
    }
}
