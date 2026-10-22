//! `connect` against the justssh server, or one answering authentication raw
//! (`justssh/test-support`), over a duplex pipe.

use justssh::{
    Action, Client, ClientConfig, Closed, DisconnectReason, Error, Event, HostKey, InfoRequest,
    Phase, Server, ServerConfig, Zeroizing,
};
use justssh_tokio::{AuthMethod, ClientHandler, Connected, Deadlines};
use justssh_wire::{Message, UserauthFailure, UserauthSuccess, Writer, number};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Accepts or refuses every host key, answers every question, and records what it was asked.
struct Handler {
    accept_host_key: bool,
    host_keys: Vec<Vec<u8>>,
    questions: usize,
}

impl Handler {
    fn accepting() -> Self {
        Handler {
            accept_host_key: true,
            host_keys: Vec::new(),
            questions: 0,
        }
    }
}

impl ClientHandler for Handler {
    async fn check_host_key(&mut self, key: &[u8]) -> bool {
        self.host_keys.push(key.to_vec());
        self.accept_host_key
    }

    async fn answer(&mut self, request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        self.questions += request.prompts().len();
        request
            .prompts()
            .iter()
            .map(|_| Zeroizing::new(b"answer".to_vec()))
            .collect()
    }
}

/// Runs the justssh server, accepting the password `pw`, against `connect` with `methods`.
/// Returns how `connect` ended, the client, the handler and the passwords the server was shown.
async fn run(
    methods: &[AuthMethod],
    handler: Handler,
) -> (
    Connected<tokio::io::DuplexStream>,
    Client,
    Handler,
    Vec<Vec<u8>>,
) {
    run_with_tries(methods, handler, 6).await
}

/// [`run`] with a server that disconnects after `max_auth_tries` failures.
async fn run_with_tries(
    methods: &[AuthMethod],
    mut handler: Handler,
    max_auth_tries: u32,
) -> (
    Connected<tokio::io::DuplexStream>,
    Client,
    Handler,
    Vec<Vec<u8>>,
) {
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let server_task = tokio::spawn(async move {
        let config = ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32])))
            .max_auth_tries(std::num::NonZeroU32::new(max_auth_tries).unwrap())
            .build();
        let mut server = Server::new(config);
        let mut shown = Vec::new();
        let _ = justssh_tokio::accept(server_io, &mut server, &Deadlines::new(), |request| {
            shown.push(request.password().to_vec());
            let ok = request.user() == b"alice" && request.password() == b"pw";
            async move { ok.then_some(()) }
        })
        .await;
        shown
    });
    let mut client = Client::new(ClientConfig::builder(b"alice").build());
    let connected = justssh_tokio::connect(
        client_io,
        &mut client,
        &Deadlines::new(),
        methods,
        &mut handler,
    )
    .await
    .unwrap();
    let shown = server_task.await.unwrap();
    (connected, client, handler, shown)
}

fn password(pw: &[u8]) -> AuthMethod {
    AuthMethod::Password(Zeroizing::new(pw.to_vec()))
}

#[tokio::test]
async fn a_password_logs_in() {
    let (connected, client, handler, shown) = run(&[password(b"pw")], Handler::accepting()).await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
    assert_eq!(client.phase(), Phase::Connected);
    assert_eq!(shown, [b"pw".to_vec()]);
    assert_eq!(handler.host_keys.len(), 1);
    assert_eq!(
        handler.host_keys[0].as_slice(),
        client.peer_host_key().unwrap()
    );
}

#[tokio::test]
async fn a_method_the_server_does_not_allow_is_passed_over() {
    let (connected, _client, handler, shown) = run_with_tries(
        &[AuthMethod::KeyboardInteractive, password(b"pw")],
        Handler::accepting(),
        1,
    )
    .await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
    assert_eq!(handler.questions, 0);
    assert_eq!(shown, [b"pw".to_vec()]);
}

#[tokio::test]
async fn a_failed_method_is_not_tried_again() {
    let (connected, _client, _handler, shown) =
        run(&[password(b"wrong"), password(b"pw")], Handler::accepting()).await;
    assert_eq!(shown, [b"wrong".to_vec()]);
    assert_eq!(
        no_method_left(connected),
        (vec!["none", "password"], vec!["password".to_owned()])
    );
}

#[tokio::test]
async fn with_no_allowed_method_left_the_client_disconnects() {
    let (connected, _client, _handler, shown) =
        run(&[AuthMethod::KeyboardInteractive], Handler::accepting()).await;
    assert!(shown.is_empty());
    assert_eq!(
        no_method_left(connected),
        (vec!["none"], vec!["password".to_owned()])
    );
}

#[tokio::test]
async fn a_refused_host_key_ends_the_connection_before_authentication() {
    let handler = Handler {
        accept_host_key: false,
        ..Handler::accepting()
    };
    let (connected, _client, _handler, shown) = run(&[password(b"pw")], handler).await;
    assert!(shown.is_empty());
    assert_eq!(
        connected_closed(connected),
        Closed::Local {
            reason: DisconnectReason::HOST_KEY_NOT_VERIFIABLE,
            error: Error::HostKeyRejected,
            phase: Phase::Handshake,
        }
    );
}

/// The methods tried and the last ones allowed, when `connect` ran out of methods.
fn no_method_left(connected: Connected<DuplexStream>) -> (Vec<&'static str>, Vec<String>) {
    match connected {
        Connected::NoMethodLeft { tried, allowed } => (tried, allowed),
        other => panic!("not out of methods: {other:?}"),
    }
}

fn connected_closed(connected: Connected<tokio::io::DuplexStream>) -> Closed {
    match connected {
        Connected::Closed(c) => c,
        other => panic!("not closed: {other:?}"),
    }
}

/// A request's method, and for `publickey` whether it is a query or signed and its algorithm.
fn describe(method: &str, data: &[u8]) -> String {
    if method != "publickey" {
        return method.to_owned();
    }
    let mut r = justssh_wire::Reader::new(data);
    let signed = r.bool().unwrap();
    let algorithm = r.utf8().unwrap();
    format!(
        "publickey {} {algorithm}",
        if signed { "signed" } else { "query" }
    )
}

/// A server that answers the `n`th authentication request with the payloads of `replies[n]`,
/// raw and in one write, and returns the authentication methods it was asked for.
async fn raw_server(mut io: DuplexStream, replies: Vec<Vec<Vec<u8>>>) -> Vec<String> {
    let config = ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
    let mut server = Server::new(config);
    let mut replies = replies.into_iter();
    let mut methods = Vec::new();
    let mut actions = server.process(Event::Connected);
    let mut buf = vec![0u8; 1 << 16];
    loop {
        for a in actions {
            match a {
                Action::Write(b) => io.write_all(&b).await.unwrap(),
                Action::RawReceived(p) => {
                    let Ok(Message::UserauthRequest(r)) = Message::decode(&p) else {
                        continue;
                    };
                    methods.push(describe(&r.method, &r.method_data));
                    if let Some(reply) = replies.next() {
                        let mut out = Vec::new();
                        for payload in reply {
                            for w in server.send_raw(&payload) {
                                if let Action::Write(b) = w {
                                    out.extend(b);
                                }
                            }
                        }
                        io.write_all(&out).await.unwrap();
                    }
                }
                _ => {}
            }
        }
        if server.phase() == Phase::Auth {
            server.set_raw_receive(true);
        }
        let n = io.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return methods;
        }
        actions = server.process(Event::Received(&buf[..n]));
    }
}

fn auth_failure(methods: &[&str]) -> Vec<u8> {
    failure_with(methods, false)
}

fn failure_with(methods: &[&str], partial_success: bool) -> Vec<u8> {
    Message::UserauthFailure(UserauthFailure::new(
        methods.iter().map(|m| (*m).to_owned()).collect(),
        partial_success,
    ))
    .encode()
}

fn auth_success() -> Vec<u8> {
    Message::UserauthSuccess(UserauthSuccess::default()).encode()
}

/// `connect` as `alice` with `methods` against [`raw_server`] answering with `replies`; how it
/// ended and the methods the server was asked for.
async fn against_raw(
    methods: &[AuthMethod],
    replies: Vec<Vec<Vec<u8>>>,
    deadlines: Deadlines,
) -> (Connected<DuplexStream>, Vec<String>) {
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(raw_server(server_io, replies));
    let mut client = Client::new(ClientConfig::builder(b"alice").build());
    let connected = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        justssh_tokio::connect(
            client_io,
            &mut client,
            &deadlines,
            methods,
            &mut Handler::accepting(),
        ),
    )
    .await
    .expect("connect is still waiting")
    .unwrap();
    let asked = match &connected {
        Connected::Authenticated { .. } => {
            server.abort();
            Vec::new()
        }
        _ => server.await.unwrap(),
    };
    (connected, asked)
}

#[tokio::test]
async fn a_failure_naming_no_methods_leaves_none_to_try() {
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(raw_server(
        server_io,
        vec![
            vec![auth_failure(&["password", "keyboard-interactive"])],
            vec![auth_failure(&[])],
        ],
    ));
    let mut client = Client::new(ClientConfig::builder(b"alice").build());
    let connected = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        justssh_tokio::connect(
            client_io,
            &mut client,
            &Deadlines::new(),
            &[password(b"pw"), AuthMethod::KeyboardInteractive],
            &mut Handler::accepting(),
        ),
    )
    .await
    .expect("connect is still waiting for an answer")
    .unwrap();
    assert_eq!(
        no_method_left(connected),
        (vec!["none", "password"], Vec::<String>::new())
    );
    drop(client);
    assert_eq!(server.await.unwrap(), ["none", "password"]);
}

#[tokio::test]
async fn a_failure_read_with_the_questions_moves_on_to_the_next_method() {
    let mut questions = Writer::new();
    questions
        .u8(number::USERAUTH_INFO_REQUEST)
        .string(b"")
        .string(b"")
        .string(b"")
        .u32(1)
        .string(b"Password: ")
        .bool(false);
    let (connected, _) = against_raw(
        &[AuthMethod::KeyboardInteractive, password(b"pw")],
        vec![
            vec![auth_failure(&["keyboard-interactive", "password"])],
            vec![questions.into_bytes(), auth_failure(&["password"])],
            vec![auth_success()],
        ],
        Deadlines::new(),
    )
    .await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
}

#[tokio::test]
async fn a_partial_success_lets_the_same_method_go_again() {
    let (connected, _) = against_raw(
        &[password(b"pw")],
        vec![
            vec![auth_failure(&["password"])],
            vec![failure_with(&["password"], true)],
            vec![auth_success()],
        ],
        Deadlines::new(),
    )
    .await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
}

#[tokio::test]
async fn the_client_gives_up_after_64_attempts() {
    let mut replies = vec![vec![auth_failure(&["password"])]];
    replies.extend((0..100).map(|_| vec![failure_with(&["password"], true)]));
    let (connected, asked) = against_raw(&[password(b"pw")], replies, Deadlines::new()).await;
    assert_eq!(
        no_method_left(connected),
        (vec!["none"], vec!["password".to_owned()])
    );
    // none, then 64 passwords: x/crypto/ssh stops once tried + partial exceeds 64.
    assert_eq!(asked.len(), 65);
    assert_eq!(asked[0], "none");
}

#[tokio::test]
async fn a_deadline_ends_connect_even_when_the_peer_reads_nothing() {
    // A pipe too small for the client's first flight, whose other end never reads.
    let (_peer, client_io) = tokio::io::duplex(8);
    let mut client = Client::new(ClientConfig::builder(b"alice").build());
    let connected = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        justssh_tokio::connect(
            client_io,
            &mut client,
            &Deadlines::new().phase(Phase::Auth, std::time::Duration::from_millis(200)),
            &[password(b"pw")],
            &mut Handler::accepting(),
        ),
    )
    .await
    .expect("connect is still waiting")
    .unwrap();
    assert_eq!(
        connected_closed(connected),
        Closed::Local {
            reason: DisconnectReason::BY_APPLICATION,
            error: Error::DeadlineExceeded,
            phase: Phase::Handshake,
        }
    );
}

#[tokio::test]
async fn a_deadline_passing_while_reading_ends_connect_when_the_disconnect_cannot_be_written() {
    // Room for the identification line but not for the DISCONNECT after it.
    let (_peer, client_io) = tokio::io::duplex(24);
    let mut client = Client::new(ClientConfig::builder(b"alice").build());
    let connected = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        justssh_tokio::connect(
            client_io,
            &mut client,
            &Deadlines::new().phase(Phase::Auth, std::time::Duration::from_millis(200)),
            &[password(b"pw")],
            &mut Handler::accepting(),
        ),
    )
    .await
    .expect("connect is still waiting")
    .unwrap();
    assert_eq!(
        connected_closed(connected),
        Closed::Local {
            reason: DisconnectReason::BY_APPLICATION,
            error: Error::DeadlineExceeded,
            phase: Phase::Handshake,
        }
    );
}

#[tokio::test]
async fn a_client_session_and_a_server_session_carry_an_exec_both_ways() {
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let server_task = tokio::spawn(async move {
        let config =
            ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
        let mut server = Server::new(config);
        let Ok(justssh_tokio::Accepted::Authenticated { io, events, .. }) =
            justssh_tokio::accept(server_io, &mut server, &Deadlines::new(), |_| async {
                Some(())
            })
            .await
        else {
            panic!("not authenticated");
        };
        let mut session = justssh_tokio::Session::new(io, server, events);
        let channel = match session.next().await.unwrap() {
            Some(Action::ChannelOpenRequest(open)) => open.channel(),
            other => panic!("{other:?}"),
        };
        session.accept_channel(channel, Vec::new()).await.unwrap();
        let (kind, data, token) = match session.next().await.unwrap() {
            Some(Action::ChannelRequest(r)) => (
                r.kind().to_str().unwrap().to_owned(),
                r.data().to_vec(),
                r.reply(),
            ),
            other => panic!("{other:?}"),
        };
        session.reply(token.unwrap(), true).await.unwrap();
        session.data(channel, b"hello\n").await.unwrap();
        session
            .request(channel, "exit-status", false, vec![0, 0, 0, 0])
            .await
            .unwrap();
        session.eof(channel).await.unwrap();
        session.close(channel).await.unwrap();
        while let Some(action) = session.next().await.unwrap() {
            if matches!(action, Action::ChannelClosed { .. }) {
                break;
            }
        }
        (kind, data)
    });

    let mut client = Client::new(ClientConfig::builder(b"alice").build());
    let Connected::Authenticated { io, events } = justssh_tokio::connect(
        client_io,
        &mut client,
        &Deadlines::new(),
        &[password(b"pw")],
        &mut Handler::accepting(),
    )
    .await
    .unwrap() else {
        panic!("not authenticated");
    };
    let mut session = justssh_tokio::Session::new(io, client, events);
    let channel = session
        .open_channel("session", Vec::new())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        session.next().await.unwrap(),
        Some(Action::ChannelOpened { channel: c, .. }) if c == channel
    ));
    let token = session
        .request(channel, "exec", true, b"\0\0\0\x02id".to_vec())
        .await
        .unwrap();
    let mut seen = Vec::new();
    while let Some(action) = session.next().await.unwrap() {
        match action {
            Action::ChannelRequestReply { token: t, ok, .. } if Some(t) == token => {
                seen.push(format!("reply {ok}"))
            }
            Action::ChannelData { data, .. } => {
                seen.push(format!("data {}", String::from_utf8_lossy(&data)))
            }
            Action::ChannelRequest(r) => seen.push(r.kind().to_str().unwrap().to_owned()),
            Action::ChannelEof { .. } => seen.push("eof".into()),
            Action::ChannelClosed { .. } => {
                seen.push("closed".into());
                break;
            }
            _ => {}
        }
    }
    assert_eq!(
        seen,
        ["reply true", "data hello\n", "exit-status", "eof", "closed"]
    );
    let (kind, data) = server_task.await.unwrap();
    assert_eq!(
        (kind.as_str(), data.as_slice()),
        ("exec", &b"\0\0\0\x02id"[..])
    );
}

#[path = "../../justssh/tests/common/test_keys.rs"]
mod test_keys;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rsa_key() -> justssh::PrivateKey {
    justssh::PrivateKey::rsa(
        &hex(test_keys::RSA_N),
        &hex(test_keys::RSA_E),
        Zeroizing::new(hex(test_keys::RSA_D)),
        Zeroizing::new(hex(test_keys::RSA_P)),
        Zeroizing::new(hex(test_keys::RSA_Q)),
    )
    .unwrap()
}

fn ed25519_key(seed: u8) -> justssh::PrivateKey {
    justssh::PrivateKey::ed25519(Zeroizing::new([seed; 32]))
}

/// An OpenSSH certificate of `cert_type` for the key in `plain_blob`; its signature is not
/// checked here.
fn certificate(cert_type: &str, plain_blob: &[u8]) -> Vec<u8> {
    let mut plain = justssh_wire::Reader::new(plain_blob);
    plain.utf8().unwrap();
    let mut w = Writer::new();
    w.string(cert_type.as_bytes()).string(b"nonce");
    w.bytes(plain.remaining());
    w.bytes(&[0; 8])
        .u32(1)
        .string(b"id")
        .string(b"")
        .bytes(&[0; 8])
        .bytes(&[0xff; 8]);
    w.string(b"")
        .string(b"")
        .string(b"")
        .string(b"ca")
        .string(b"sig");
    w.into_bytes()
}

fn pk_ok(algorithm: &str, blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(number::USERAUTH_PK_OK)
        .string(algorithm.as_bytes())
        .string(blob);
    w.into_bytes()
}

#[tokio::test]
async fn keys_are_offered_in_turn_until_one_is_accepted() {
    let (first, second) = (ed25519_key(1), ed25519_key(2));
    let (connected, asked) = against_raw_asked(
        &[AuthMethod::PublicKeys(vec![first, second.clone()])],
        vec![
            vec![auth_failure(&["publickey"])],
            vec![auth_failure(&["publickey"])],
            vec![pk_ok("ssh-ed25519", &second.public_blob())],
            vec![auth_success()],
        ],
    )
    .await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
    assert_eq!(
        asked,
        [
            "none",
            "publickey query ssh-ed25519",
            "publickey query ssh-ed25519",
            "publickey signed ssh-ed25519",
        ]
    );
}

#[tokio::test]
async fn an_rsa_certificate_refused_under_rsa_sha2_is_offered_again_as_ssh_rsa_cert() {
    let key = rsa_key();
    let cert = certificate("ssh-rsa-cert-v01@openssh.com", &key.public_blob());
    let key = key.with_certificate(cert.clone()).unwrap();
    let (connected, asked) = against_raw_asked(
        &[AuthMethod::PublicKeys(vec![key])],
        vec![
            vec![auth_failure(&["publickey"])],
            vec![auth_failure(&["publickey"])],
            vec![pk_ok("ssh-rsa-cert-v01@openssh.com", &cert)],
            vec![auth_success()],
        ],
    )
    .await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
    assert_eq!(
        asked,
        [
            "none",
            "publickey query rsa-sha2-256-cert-v01@openssh.com",
            "publickey query ssh-rsa-cert-v01@openssh.com",
            "publickey signed ssh-rsa-cert-v01@openssh.com",
        ]
    );
}

#[tokio::test]
async fn a_signed_key_refused_without_publickey_left_moves_to_the_next_method() {
    let (first, second) = (ed25519_key(1), ed25519_key(2));
    let (connected, asked) = against_raw_asked(
        &[
            AuthMethod::PublicKeys(vec![first.clone(), second]),
            password(b"pw"),
        ],
        vec![
            vec![auth_failure(&["publickey", "password"])],
            vec![pk_ok("ssh-ed25519", &first.public_blob())],
            vec![auth_failure(&["password"])],
            vec![auth_success()],
        ],
    )
    .await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
    assert_eq!(
        asked,
        [
            "none",
            "publickey query ssh-ed25519",
            "publickey signed ssh-ed25519",
            "password",
        ]
    );
}

#[tokio::test]
async fn when_every_key_is_refused_the_next_method_is_tried() {
    let (first, second) = (ed25519_key(1), ed25519_key(2));
    let (connected, asked) = against_raw_asked(
        &[AuthMethod::PublicKeys(vec![first, second]), password(b"pw")],
        vec![
            vec![auth_failure(&["publickey", "password"])],
            vec![auth_failure(&["publickey", "password"])],
            vec![auth_failure(&["publickey", "password"])],
            vec![auth_success()],
        ],
    )
    .await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
    assert_eq!(
        asked,
        [
            "none",
            "publickey query ssh-ed25519",
            "publickey query ssh-ed25519",
            "password",
        ]
    );
}

#[tokio::test]
async fn an_empty_key_list_is_passed_over() {
    let (connected, asked) = against_raw_asked(
        &[AuthMethod::PublicKeys(Vec::new()), password(b"pw")],
        vec![
            vec![auth_failure(&["publickey", "password"])],
            vec![auth_success()],
        ],
    )
    .await;
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
    assert_eq!(asked, ["none", "password"]);
}

/// [`against_raw`] for a connection that authenticates: the server is asked to stop once the
/// client is in, and what it was asked comes back.
async fn against_raw_asked(
    methods: &[AuthMethod],
    replies: Vec<Vec<Vec<u8>>>,
) -> (Connected<DuplexStream>, Vec<String>) {
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(raw_server(server_io, replies));
    let mut client = Client::new(ClientConfig::builder(b"alice").build());
    let connected = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        justssh_tokio::connect(
            client_io,
            &mut client,
            &Deadlines::new(),
            methods,
            &mut Handler::accepting(),
        ),
    )
    .await
    .expect("connect is still waiting")
    .unwrap();
    let connected = match connected {
        Connected::Authenticated { io, events } => {
            drop(io);
            Connected::Authenticated {
                io: tokio::io::duplex(1).0,
                events,
            }
        }
        other => other,
    };
    let asked = server.await.unwrap();
    (connected, asked)
}
