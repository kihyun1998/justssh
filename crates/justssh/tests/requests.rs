use justssh::DecodeError;
use justssh::requests::{Env, Exec, ExitSignal, ExitStatus, PtyReq, Shell, Subsystem};
use proptest::prelude::*;

fn string(d: &mut Vec<u8>, s: &[u8]) {
    d.extend((s.len() as u32).to_be_bytes());
    d.extend(s);
}

/// pty-req data as a client sends it: `term`, 80x24 characters, 0x0 pixels, and `modes` as
/// opcode/value pairs closed by TTY_OP_END.
fn pty_req_data(term: &[u8], modes: &[(u8, u32)]) -> Vec<u8> {
    let mut d = Vec::new();
    string(&mut d, term);
    for v in [80u32, 24, 0, 0] {
        d.extend(v.to_be_bytes());
    }
    let mut m = Vec::new();
    for (op, v) in modes {
        m.push(*op);
        m.extend(v.to_be_bytes());
    }
    m.push(0);
    string(&mut d, &m);
    d
}

/// A client, its `TERM` and its modes.
type Measured = (&'static str, &'static [u8], &'static [(u8, u32)]);

/// The modes measured through acwbroker (#5), in the order each client sent them.
const MEASURED: [Measured; 4] = [
    (
        "PuTTY 0.83",
        b"xterm",
        &[(3, 127), (42, 1), (128, 38400), (129, 38400)],
    ),
    (
        "SecureCRT 9.0.2",
        b"xterm-256color",
        &[
            (1, 3),
            (5, 4),
            (4, 21),
            (8, 17),
            (9, 19),
            (10, 26),
            (12, 18),
            (13, 23),
            (14, 22),
            (2, 28),
            (128, 38400),
            (129, 38400),
        ],
    ),
    ("Xshell 7", b"xterm", &[(128, 38400), (129, 38400)]),
    (
        "MobaXterm (MoTTY 0.83)",
        b"xterm",
        &[(3, 8), (39, 1), (42, 1), (128, 38400), (129, 38400)],
    ),
];

#[test]
fn measured_pty_requests_read_as_sent_and_encode_back_to_the_same_bytes() {
    for (client, term, modes) in MEASURED {
        let data = pty_req_data(term, modes);
        let pty = PtyReq::decode(&data).unwrap();
        assert_eq!(pty.term(), term, "{client}");
        assert_eq!(
            (pty.columns(), pty.rows(), pty.width(), pty.height()),
            (80, 24, 0, 0),
            "{client}"
        );
        assert_eq!(pty.modes().collect::<Vec<_>>(), modes, "{client}");
        assert_eq!(pty.encode(), data, "{client}");
    }
}

#[test]
fn a_pty_request_built_from_modes_is_what_a_client_sends() {
    let (_, term, modes) = MEASURED[1];
    assert_eq!(
        PtyReq::new(term.to_vec(), 80, 24, 0, 0, modes).encode(),
        pty_req_data(term, modes)
    );
}

#[test]
fn modes_after_an_undefined_opcode_are_kept_but_not_read() {
    let m = vec![159, 0, 0, 0, 9, 200, 1, 2, 3, 4];
    let mut data = pty_req_data(b"vt100", &[]);
    data.truncate(data.len() - 5);
    string(&mut data, &m);
    let pty = PtyReq::decode(&data).unwrap();
    assert_eq!(pty.modes().collect::<Vec<_>>(), [(159, 9)]);
    assert_eq!(pty.encoded_modes(), m);
    assert_eq!(pty.encode(), data);
}

#[test]
fn modes_after_tty_op_end_are_kept_but_not_read() {
    let m = [3, 0, 0, 0, 127, 0, 4, 0, 0, 0, 21];
    let mut data = pty_req_data(b"vt100", &[]);
    data.truncate(data.len() - 5);
    string(&mut data, &m);
    let pty = PtyReq::decode(&data).unwrap();
    assert_eq!(pty.modes().collect::<Vec<_>>(), [(3, 127)]);
    assert_eq!(pty.encode(), data);
}

#[test]
fn reading_modes_stays_stopped_at_an_undefined_opcode() {
    let pty = PtyReq::from_encoded_modes(b"vt100".to_vec(), 80, 24, 0, 0, vec![200, 3, 0, 0, 0, 5]);
    let mut modes = pty.modes();
    assert_eq!((modes.next(), modes.next()), (None, None));
}

#[test]
fn a_pty_request_built_from_encoded_modes_sends_them_as_given() {
    let m = vec![3, 0, 0, 0, 127, 0, 9, 9];
    let pty = PtyReq::from_encoded_modes(b"xterm".to_vec(), 80, 24, 0, 0, m.clone());
    let mut data = pty_req_data(b"xterm", &[]);
    data.truncate(data.len() - 5);
    string(&mut data, &m);
    assert_eq!(pty.encode(), data);
    assert_eq!(PtyReq::decode(&data).unwrap(), pty);
}

#[test]
fn modes_cut_off_in_a_value_read_up_to_the_cut() {
    let mut data = pty_req_data(b"vt100", &[]);
    data.truncate(data.len() - 5);
    string(&mut data, &[3, 0, 0, 0, 127, 4, 0, 0]);
    let pty = PtyReq::decode(&data).unwrap();
    assert_eq!(pty.modes().collect::<Vec<_>>(), [(3, 127)]);
    assert_eq!(pty.encode(), data);
}

#[test]
fn a_core_dump_flag_other_than_one_reads_true_and_encodes_back_as_sent() {
    let mut data = Vec::new();
    string(&mut data, b"SEGV");
    data.push(2);
    string(&mut data, b"");
    string(&mut data, b"");
    let signal = ExitSignal::decode(&data).unwrap();
    assert!(signal.core_dumped());
    assert_eq!(signal.encode(), data);
}

#[test]
fn trailing_bytes_are_refused() {
    let mut exec = Vec::new();
    string(&mut exec, b"ls");
    exec.push(0);
    assert_eq!(Exec::decode(&exec).err(), Some(DecodeError::TrailingBytes));
    assert_eq!(
        ExitStatus::decode(&[0, 0, 0, 1, 0]).err(),
        Some(DecodeError::TrailingBytes)
    );
    assert_eq!(Shell::decode(&[0]).err(), Some(DecodeError::TrailingBytes));
    let mut pty = pty_req_data(b"xterm", &[]);
    pty.push(0);
    assert_eq!(PtyReq::decode(&pty).err(), Some(DecodeError::TrailingBytes));
}

#[test]
fn each_codec_names_its_request_type() {
    assert_eq!(
        [
            PtyReq::KIND,
            Shell::KIND,
            Exec::KIND,
            Subsystem::KIND,
            Env::KIND,
            ExitStatus::KIND,
            ExitSignal::KIND
        ],
        [
            "pty-req",
            "shell",
            "exec",
            "subsystem",
            "env",
            "exit-status",
            "exit-signal"
        ]
    );
}

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..48)
}

/// Data shaped like each request type, with arbitrary contents in every field.
fn request_data() -> impl Strategy<Value = (&'static str, Vec<u8>)> {
    prop_oneof![
        (bytes(), any::<[u32; 4]>(), bytes()).prop_map(|(t, n, m)| {
            let mut d = Vec::new();
            string(&mut d, &t);
            for v in n {
                d.extend(v.to_be_bytes());
            }
            string(&mut d, &m);
            ("pty-req", d)
        }),
        Just(("shell", Vec::new())),
        bytes().prop_map(|c| {
            let mut d = Vec::new();
            string(&mut d, &c);
            ("exec", d)
        }),
        bytes().prop_map(|n| {
            let mut d = Vec::new();
            string(&mut d, &n);
            ("subsystem", d)
        }),
        (bytes(), bytes()).prop_map(|(n, v)| {
            let mut d = Vec::new();
            string(&mut d, &n);
            string(&mut d, &v);
            ("env", d)
        }),
        any::<u32>().prop_map(|s| ("exit-status", s.to_be_bytes().to_vec())),
        (bytes(), any::<u8>(), bytes(), bytes()).prop_map(|(s, c, m, l)| {
            let mut d = Vec::new();
            string(&mut d, &s);
            d.push(c);
            string(&mut d, &m);
            string(&mut d, &l);
            ("exit-signal", d)
        }),
    ]
}

/// Decodes `data` with the codec for `kind` and encodes it again.
fn reencode(kind: &str, data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    match kind {
        PtyReq::KIND => PtyReq::decode(data).map(|r| r.encode()),
        Shell::KIND => Shell::decode(data).map(|r| r.encode()),
        Exec::KIND => Exec::decode(data).map(|r| r.encode()),
        Subsystem::KIND => Subsystem::decode(data).map(|r| r.encode()),
        Env::KIND => Env::decode(data).map(|r| r.encode()),
        ExitStatus::KIND => ExitStatus::decode(data).map(|r| r.encode()),
        ExitSignal::KIND => ExitSignal::decode(data).map(|r| r.encode()),
        _ => unreachable!(),
    }
}

proptest! {
    #[test]
    fn request_data_read_through_its_codec_encodes_back_to_the_same_bytes(
        (kind, data) in request_data()
    ) {
        prop_assert_eq!(reencode(kind, &data), Ok(data));
    }

    #[test]
    fn built_requests_read_back_as_built(
        term in bytes(),
        size in any::<[u32; 4]>(),
        modes in prop::collection::vec((1u8..160, any::<u32>()), 0..8),
        a in bytes(),
        b in bytes(),
        status in any::<u32>(),
        core in any::<bool>(),
    ) {
        let pty = PtyReq::decode(
            &PtyReq::new(term.clone(), size[0], size[1], size[2], size[3], &modes).encode(),
        ).unwrap();
        prop_assert_eq!(pty.term(), &term[..]);
        prop_assert_eq!([pty.columns(), pty.rows(), pty.width(), pty.height()], size);
        prop_assert_eq!(pty.modes().collect::<Vec<_>>(), modes);
        prop_assert_eq!(Exec::decode(&Exec::new(a.clone()).encode()).unwrap().command().to_vec(), a.clone());
        prop_assert_eq!(
            Subsystem::decode(&Subsystem::new(a.clone()).encode()).unwrap().name().to_vec(),
            a.clone()
        );
        let env = Env::decode(&Env::new(a.clone(), b.clone()).encode()).unwrap();
        prop_assert_eq!((env.name(), env.value()), (&a[..], &b[..]));
        prop_assert_eq!(ExitStatus::decode(&ExitStatus::new(status).encode()).unwrap().status(), status);
        let signal = ExitSignal::decode(
            &ExitSignal::new(a.clone(), core, b.clone(), term.clone()).encode(),
        ).unwrap();
        prop_assert_eq!(
            (signal.signal(), signal.core_dumped(), signal.message(), signal.language()),
            (&a[..], core, &b[..], &term[..])
        );
        prop_assert!(Shell::decode(&Shell::new().encode()).is_ok());
    }
}
