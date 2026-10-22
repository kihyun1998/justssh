//! The handoff codec against the byte layouts acwbroker writes down by hand
//! (`internal/infrastructure/handoff/golden_test.go`, `golden_rule_test.go`, and the blackbox
//! harness's `codec_test.go`), and its refusals as acwbroker's `DecodeIssue` makes them.

use std::io::Cursor;
use std::time::Duration;

use justssh_broker::handoff::{self, Kind, ReadError};
use justssh_broker::issue::{self, IssueError, Method};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const HELLO_GOLDEN: &str = "01000000040000000b0200000012\
                            41435742524f4b45522050524f544f203131";
const LISTENING_GOLDEN: &str = "210000000f3132372e302e302e313a3531323330\
                                22000000330000000b7373682d6564323535313900000020\
                                1111111111111111111111111111111111111111111111111111111111111111";
const REFUSAL_GOLDEN: &str = "300000001077726f6e672070617373706872617365310000000101";
const PLAIN_ERROR_GOLDEN: &str = "30000000146c697374656e657220756e617661696c61626c65";
const TOKEN_GOLDEN: &str =
    "20000000203030313132323333343435353636373738383939616162626363646465656666";
const ISSUE_GOLDEN: &str = "100000000870617373776f7264\
                            150000000e73727634324031302e302e302e39\
                            160000000f3132372e302e302e373a3531323031\
                            11000000027077";
const NO_TRANSFER_ISSUE_GOLDEN: &str = "100000000870617373776f7264\
                                        150000000e73727634324031302e302e302e39\
                                        160000000f3132372e302e302e373a3531323031\
                                        180000000101\
                                        11000000027077";
const BOUND_ISSUE_GOLDEN: &str = "100000000870617373776f7264\
                                  150000000e73727634324031302e302e302e39\
                                  160000000f3132372e302e302e373a3531323031\
                                  170000000410000004\
                                  11000000027077";
const CERT_ISSUE_GOLDEN: &str = "100000000b6365727469666963617465\
                                 150000000e73727634324031302e302e302e39\
                                 160000000f3132372e302e302e373a3531323031\
                                 12000000034b4559\
                                 13000000025050\
                                 140000000443455254";
const RULED_ISSUE_GOLDEN: &str = "100000000870617373776f7264\
    150000000e73727634324031302e302e302e39\
    160000000f3132372e302e302e373a3531323031\
    190000000103\
    1a00000012433a5c6d5c4d6f6261587465726d2e657865\
    1b000000074d6f626174656b\
    1c000000094d6f6261587465726d\
    1d000000094d6f6261587465726d\
    1e0000001d433a5c735c5f7373682e65786500433a5c735c785c5f7373682e657865\
    1f0000000400001388\
    11000000027077";

#[test]
fn what_the_broker_writes_matches_the_documented_layouts() {
    let host_key = [
        &[0, 0, 0, 0x0b][..],
        b"ssh-ed25519",
        &[0, 0, 0, 0x20],
        &[0x11; 32],
    ]
    .concat();
    assert_eq!(handoff::hello(11), unhex(HELLO_GOLDEN));
    assert_eq!(
        handoff::listening("127.0.0.1:51230", &host_key),
        unhex(LISTENING_GOLDEN)
    );
    assert_eq!(
        handoff::refusal("wrong passphrase", 1),
        unhex(REFUSAL_GOLDEN)
    );
    assert_eq!(
        handoff::error("listener unavailable"),
        unhex(PLAIN_ERROR_GOLDEN)
    );
    assert_eq!(
        *handoff::token("00112233445566778899aabbccddeeff"),
        unhex(TOKEN_GOLDEN)
    );
}

#[test]
fn a_frame_is_its_kind_its_length_and_its_payload() {
    let mut out = Vec::new();
    handoff::write_frame(&mut out, Kind::Hello, &unhex(HELLO_GOLDEN)).unwrap();
    assert_eq!(out, unhex(&format!("0100000020{HELLO_GOLDEN}")));
    let frame = handoff::read_frame(&mut Cursor::new(&out)).unwrap();
    assert_eq!(
        (frame.kind, &frame.payload[..]),
        (1, &unhex(HELLO_GOLDEN)[..])
    );
}

#[test]
fn the_frame_kinds_keep_their_bytes() {
    let kinds = [
        (Kind::Hello, 0x01),
        (Kind::Issue, 0x02),
        (Kind::Token, 0x03),
        (Kind::Listening, 0x04),
        (Kind::Error, 0x05),
        (Kind::Freeze, 0x07),
        (Kind::Attach, 0x08),
    ];
    for (kind, byte) in kinds {
        assert_eq!(kind as u8, byte, "{kind:?}");
    }
}

#[test]
fn a_clean_end_a_cut_frame_and_an_oversized_length_are_told_apart() {
    assert!(matches!(
        handoff::read_frame(&mut Cursor::new(b"")),
        Err(ReadError::Closed)
    ));
    for cut in [
        &b"\x02\x00\x00"[..],
        b"\x02\x00\x00\x00\x02",
        b"\x02\x00\x00\x00\x02p",
    ] {
        assert!(
            matches!(
                handoff::read_frame(&mut Cursor::new(cut)),
                Err(ReadError::Truncated)
            ),
            "{cut:x?}"
        );
    }
    let at_cap = [&[2, 0, 0x10, 0, 0][..], &vec![0; 1 << 20]].concat();
    assert_eq!(
        handoff::read_frame(&mut Cursor::new(&at_cap))
            .unwrap()
            .payload
            .len(),
        1 << 20
    );
    assert!(matches!(
        handoff::read_frame(&mut Cursor::new(b"\x02\x00\x10\x00\x01")),
        Err(ReadError::TooLong(0x0010_0001))
    ));
    assert!(matches!(
        handoff::read_frame(&mut Cursor::new(b"\x02\x7f\xff\xff\xff")),
        Err(ReadError::TooLong(0x7fff_ffff))
    ));
    assert!(handoff::write_frame(&mut Vec::new(), Kind::Error, &vec![0; (1 << 20) + 1]).is_err());
}

#[test]
fn a_hello_needs_a_version_of_four_bytes_and_nothing_unknown() {
    assert_eq!(handoff::decode_hello(&unhex(HELLO_GOLDEN)), Ok(11));
    assert_eq!(handoff::decode_hello(&unhex("010000000400000007")), Ok(7));
    for bad in [
        "",
        "0200000000",
        "0100000003000000",
        "01000000040000000b01000000040000000b",
        "01000000040000000b0300000000",
        "0100000004000000",
    ] {
        assert!(handoff::decode_hello(&unhex(bad)).is_err(), "{bad}");
    }
}

#[test]
fn a_freeze_and_an_attach_are_read_as_acwbroker_reads_them() {
    assert_eq!(
        handoff::decode_freeze(&unhex("40000000040000beef")),
        Ok(0xbeef)
    );
    for bad in [
        "",
        "4000000004000000",
        "400000000400000000",
        "40000000040000beef01000000",
    ] {
        assert!(handoff::decode_freeze(&unhex(bad)).is_err(), "{bad}");
    }
    let token = "200000000430303131";
    for good in [
        format!("{token}500000000143"),
        format!("{token}51000000040000beef"),
        format!("{token}500000000143510000000400000001"),
    ] {
        assert!(handoff::decode_attach(&unhex(&good)).is_ok(), "{good}");
    }
    for bad in [
        token.to_owned(),
        "500000000143".to_owned(),
        format!("{token}5000000000"),
        format!("{token}510000000400000000"),
        format!("{token}5100000003000000"),
        "2000000000500000000143".to_owned(),
    ] {
        assert!(handoff::decode_attach(&unhex(&bad)).is_err(), "{bad}");
    }
}

#[test]
fn the_documented_issues_read_as_acwbroker_reads_them() {
    let iss = issue::decode(&unhex(ISSUE_GOLDEN)).unwrap();
    assert_eq!(iss.method, Method::Password);
    assert_eq!(iss.username, b"srv42@10.0.0.9");
    assert_eq!(iss.upstream, b"127.0.0.7:51201");
    assert_eq!(iss.password.as_deref().map(|p| &p[..]), Some(&b"pw"[..]));
    assert!(!iss.no_file_transfer && iss.terminal.is_none() && iss.grace.is_none());
    assert!(iss.rule.is_none());

    assert!(
        issue::decode(&unhex(NO_TRANSFER_ISSUE_GOLDEN))
            .unwrap()
            .no_file_transfer
    );
    assert_eq!(
        issue::decode(&unhex(BOUND_ISSUE_GOLDEN)).unwrap().terminal,
        Some(268_435_460)
    );

    let cert = issue::decode(&unhex(CERT_ISSUE_GOLDEN)).unwrap();
    assert_eq!(cert.method, Method::Certificate);
    assert_eq!(
        cert.private_key.as_deref().map(|p| &p[..]),
        Some(&b"KEY"[..])
    );
    assert_eq!(cert.passphrase.as_deref().map(|p| &p[..]), Some(&b"PP"[..]));
    assert_eq!(
        cert.certificate.as_deref().map(|p| &p[..]),
        Some(&b"CERT"[..])
    );

    let ruled = issue::decode(&unhex(RULED_ISSUE_GOLDEN)).unwrap();
    assert_eq!(ruled.grace, Some(Duration::from_secs(5)));
    let rule = ruled.rule.unwrap();
    assert_eq!(rule.kind, 3);
    assert_eq!(rule.path, br"C:\m\MobaXterm.exe");
    assert_eq!(
        rule.metadata,
        Some((
            b"Mobatek".to_vec(),
            b"MobaXterm".to_vec(),
            b"MobaXterm".to_vec()
        ))
    );
    assert_eq!(
        rule.extra_paths,
        [br"C:\s\_ssh.exe".to_vec(), br"C:\s\x\_ssh.exe".to_vec()]
    );
}

/// A TLV record.
fn rec(tag: u8, val: &[u8]) -> Vec<u8> {
    [&[tag][..], &(val.len() as u32).to_be_bytes(), val].concat()
}

/// A password ISSUE for `127.0.0.7:51201` with `extra` before the password.
fn password_issue(extra: &[u8]) -> Vec<u8> {
    [
        rec(0x10, b"password"),
        rec(0x15, b"srv42@10.0.0.9"),
        rec(0x16, b"127.0.0.7:51201"),
        extra.to_vec(),
        rec(0x11, b"pw"),
    ]
    .concat()
}

#[test]
fn a_payload_that_will_not_parse_is_malformed() {
    let good = password_issue(&[]);
    let cases = [
        [&good[..], &rec(0x23, b"")].concat(),
        [&good[..], &rec(0x11, b"pw2")].concat(),
        [&good[..], &[0x11, 0, 0]].concat(),
        [&good[..], &[0x11, 0, 0, 0, 9, b'x']].concat(),
        [&good[..], &rec(0x40, b"\0\0\0\x01")].concat(),
    ];
    for payload in cases {
        assert_eq!(
            issue::decode(&payload).err(),
            Some(IssueError::Malformed),
            "{payload:x?}"
        );
    }
}

#[test]
fn an_issue_that_parses_but_cannot_be_used_is_refused() {
    let rule = |kind: u8, extra: &[Vec<u8>]| {
        [&[rec(0x19, &[kind]), rec(0x1a, b"C:\\p.exe")][..], extra]
            .concat()
            .concat()
    };
    let without = |tag: u8| {
        let mut out = Vec::new();
        for (t, v) in [
            (0x10, &b"password"[..]),
            (0x15, b"srv42@10.0.0.9"),
            (0x16, b"127.0.0.7:51201"),
            (0x11, b"pw"),
        ] {
            if t != tag {
                out.extend(rec(t, v));
            }
        }
        out
    };
    let cases = [
        without(0x10),
        without(0x15),
        without(0x16),
        without(0x11),
        [
            rec(0x10, b"key"),
            rec(0x15, b"u"),
            rec(0x16, b"127.0.0.1:2"),
        ]
        .concat(),
        [
            rec(0x10, b"certificate"),
            rec(0x15, b"u"),
            rec(0x16, b"127.0.0.1:2"),
            rec(0x12, b"K"),
        ]
        .concat(),
        [
            rec(0x10, b"certificate"),
            rec(0x15, b"u"),
            rec(0x16, b"127.0.0.1:2"),
            rec(0x14, b"C"),
        ]
        .concat(),
        [
            rec(0x10, b"Password"),
            rec(0x15, b"u"),
            rec(0x16, b"127.0.0.1:2"),
            rec(0x11, b"p"),
        ]
        .concat(),
        [
            rec(0x10, b"password"),
            rec(0x15, b"u"),
            rec(0x16, b"127.0.0.1:2"),
            rec(0x11, b""),
        ]
        .concat(),
        password_issue(&rec(0x17, b"\0\0\x04")),
        password_issue(&rec(0x18, b"\x02")),
        password_issue(&rec(0x18, b"\x01\x01")),
        password_issue(&rec(0x18, b"")),
        password_issue(&rec(0x1f, b"\0\0\xea\x61")),
        password_issue(&rec(0x1f, b"\0\0\x13")),
        password_issue(&rec(0x1a, b"C:\\p.exe")),
        password_issue(&rec(0x1e, b"C:\\x.exe")),
        password_issue(&rule(0, &[])),
        password_issue(&rule(4, &[])),
        password_issue(&[rec(0x19, b"\x01\x01"), rec(0x1a, b"C:\\p.exe")].concat()),
        password_issue(&[rec(0x19, b"\x01"), rec(0x1a, b"")].concat()),
        password_issue(&rec(0x19, b"\x01")),
        password_issue(&rule(1, &[rec(0x1b, b"Mobatek")])),
        password_issue(&rule(3, &[rec(0x1b, b"M"), rec(0x1c, b"P")])),
        password_issue(&rule(
            3,
            &[rec(0x1b, b"M"), rec(0x1c, b"P"), rec(0x1d, b"")],
        )),
        password_issue(&rule(2, &[rec(0x1e, b"C:\\a\0\0C:\\b")])),
        password_issue(&rule(2, &[rec(0x1e, b"")])),
    ];
    for payload in cases {
        assert_eq!(
            issue::decode(&payload).err(),
            Some(IssueError::Refused),
            "{payload:x?}"
        );
    }
}

#[test]
fn the_edges_of_what_an_issue_may_carry_are_accepted() {
    let accepted = [
        password_issue(&rec(0x1f, b"\0\0\xea\x60")),
        password_issue(&rec(0x1f, b"\0\0\0\0")),
        password_issue(&rec(0x17, b"\xff\xff\xff\xff")),
        password_issue(&[rec(0x19, b"\x02"), rec(0x1a, b"C:\\p.exe")].concat()),
        password_issue(
            &[
                rec(0x19, b"\x03"),
                rec(0x1a, b"p"),
                rec(0x1b, b""),
                rec(0x1c, b""),
                rec(0x1d, b"o"),
            ]
            .concat(),
        ),
        [
            rec(0x10, b"key"),
            rec(0x15, b""),
            rec(0x16, b"[::1]:2"),
            rec(0x12, b"K"),
        ]
        .concat(),
    ];
    for payload in accepted {
        assert!(issue::decode(&payload).is_ok(), "{payload:x?}");
    }
    let iss = issue::decode(&password_issue(&rec(0x17, b"\xff\xff\xff\xff"))).unwrap();
    assert_eq!(iss.terminal, Some(-1));
    let iss = issue::decode(&password_issue(&rec(0x1f, b"\0\0\0\0"))).unwrap();
    assert_eq!(iss.grace, Some(Duration::ZERO));
}

/// acwbroker's `model.RequireLoopback` on each address, as Go 1.26.3 printed it: `Ok` for a
/// loopback address, `NotLoopback` for a host that is not one, `Refused` where the address does
/// not split into a host and a port.
const LOOPBACK: &[(&[u8], Option<IssueError>)] = &[
    (b"127.0.0.1:22", None),
    (b"127.0.0.7:51201", None),
    (b"127.255.255.255:1", None),
    (b"126.0.0.1:22", Some(IssueError::NotLoopback)),
    (b"10.0.0.9:22", Some(IssueError::NotLoopback)),
    (b"[::1]:22", None),
    (b"::1:22", Some(IssueError::Refused)),
    (b"[::1]", Some(IssueError::Refused)),
    (b"[::1]:", Some(IssueError::Refused)),
    (b"127.0.0.1:", Some(IssueError::Refused)),
    (b"127.0.0.1", Some(IssueError::Refused)),
    (b":22", Some(IssueError::NotLoopback)),
    (b"", Some(IssueError::Refused)),
    (b"localhost:22", Some(IssueError::NotLoopback)),
    (b"[::ffff:127.0.0.1]:22", None),
    (b"[::ffff:7f00:1]:22", None),
    (b"[0:0:0:0:0:0:0:1]:22", None),
    (b"[::2]:22", Some(IssueError::NotLoopback)),
    (b"127.000.0.1:22", Some(IssueError::NotLoopback)),
    (b"0127.0.0.1:22", Some(IssueError::NotLoopback)),
    (b"127.0.0.1:abc", None),
    (b"127.0.0.1:\xff", None),
    (b"[127.0.0.1]:22", None),
    (b"[::1%lo]:22", Some(IssueError::NotLoopback)),
    (b"[fe80::1%eth0]:22", Some(IssueError::NotLoopback)),
    (b"127.0.0.1:22:33", Some(IssueError::Refused)),
    (b"[::1]x:22", Some(IssueError::Refused)),
    (b"[::1]:22]", Some(IssueError::Refused)),
    (b"1[27.0.0.1:22", Some(IssueError::Refused)),
    (b" 127.0.0.1:22", Some(IssueError::NotLoopback)),
    (b"127.0.0.1 :22", Some(IssueError::NotLoopback)),
    (b"[::1]]:22", Some(IssueError::Refused)),
    (b"0.0.0.0:22", Some(IssueError::NotLoopback)),
    (b"[::]:22", Some(IssueError::NotLoopback)),
    (b"[::127.0.0.1]:22", Some(IssueError::NotLoopback)),
    (b"127.1:22", Some(IssueError::NotLoopback)),
    (b"2130706433:22", Some(IssueError::NotLoopback)),
];

#[test]
fn the_upstream_must_be_a_loopback_address_as_go_reads_one() {
    for (addr, expected) in LOOPBACK {
        let payload = [
            rec(0x10, b"password"),
            rec(0x15, b"u"),
            rec(0x16, addr),
            rec(0x11, b"pw"),
        ]
        .concat();
        assert_eq!(
            issue::decode(&payload).err(),
            *expected,
            "{}",
            addr.escape_ascii()
        );
        assert_eq!(
            issue::require_loopback(addr).err(),
            *expected,
            "{}",
            addr.escape_ascii()
        );
    }
}

#[test]
fn an_issue_shows_its_secrets_only_as_present() {
    let payload = [
        rec(0x10, b"certificate"),
        rec(0x15, b"srv42@10.0.0.9"),
        rec(0x16, b"127.0.0.7:51201"),
        rec(0x12, b"PRIVATE-KEY-BYTES"),
        rec(0x13, b"PASSPHRASE-BYTES"),
        rec(0x14, b"CERTIFICATE-BYTES"),
    ]
    .concat();
    let shown = format!("{:?}", issue::decode(&payload).unwrap());
    assert!(shown.contains("private_key: Some("), "{shown}");
    let issue = issue::decode(&password_issue(&[])).unwrap();
    let shown = [shown, format!("{issue:?}")].concat();
    for secret in [&b"PRIVATE-KEY"[..], b"PASSPHRASE-", b"CERTIFICATE-", b"pw"] {
        let text = String::from_utf8(secret.to_vec()).unwrap();
        let numbers = format!("{:?}", secret);
        let numbers = numbers.trim_matches(|c| c == '[' || c == ']');
        assert!(
            !shown.contains(&format!("\"{text}\"")) && !shown.contains(numbers),
            "{shown}"
        );
    }
}
