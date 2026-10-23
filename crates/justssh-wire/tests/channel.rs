use justssh_wire::{
    ChannelClose, ChannelData, ChannelEof, ChannelExtendedData, ChannelFailure, ChannelOpen,
    ChannelOpenConfirmation, ChannelOpenFailure, ChannelRequest, ChannelSuccess,
    ChannelWindowAdjust, Message,
};
use proptest::prelude::*;

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

fn name() -> impl Strategy<Value = String> {
    "[a-z0-9@.-]{1,32}"
}

fn channel_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        (name(), any::<u32>(), any::<u32>(), any::<u32>(), bytes()).prop_map(|(k, s, w, m, d)| {
            Message::ChannelOpen(ChannelOpen::new(k.into(), s, w, m, d))
        }),
        (
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            bytes()
        )
            .prop_map(|(r, s, w, m, d)| {
                Message::ChannelOpenConfirmation(ChannelOpenConfirmation::new(r, s, w, m, d))
            }),
        (any::<u32>(), any::<u32>(), bytes(), bytes()).prop_map(|(r, c, d, l)| {
            Message::ChannelOpenFailure(ChannelOpenFailure::new(r, c, d, l))
        }),
        (any::<u32>(), any::<u32>())
            .prop_map(|(r, b)| Message::ChannelWindowAdjust(ChannelWindowAdjust::new(r, b))),
        (any::<u32>(), bytes()).prop_map(|(r, d)| Message::ChannelData(ChannelData::new(r, d))),
        (any::<u32>(), any::<u32>(), bytes()).prop_map(|(r, c, d)| {
            Message::ChannelExtendedData(ChannelExtendedData::new(r, c, d))
        }),
        any::<u32>().prop_map(|r| Message::ChannelEof(ChannelEof::new(r))),
        any::<u32>().prop_map(|r| Message::ChannelClose(ChannelClose::new(r))),
        (any::<u32>(), name(), any::<bool>(), bytes()).prop_map(|(r, k, w, d)| {
            Message::ChannelRequest(ChannelRequest::new(r, k.into(), w, d))
        }),
        any::<u32>().prop_map(|r| Message::ChannelSuccess(ChannelSuccess::new(r))),
        any::<u32>().prop_map(|r| Message::ChannelFailure(ChannelFailure::new(r))),
    ]
}

proptest! {
    #[test]
    fn every_channel_message_survives_encode_then_decode(m in channel_message()) {
        prop_assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }
}

/// PuTTY 0.83's pty-req as measured through acwbroker: TERM xterm, 80x24, modes
/// 3=127 42=1 128=38400 129=38400.
fn putty_pty_req_data() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend([0, 0, 0, 5]);
    d.extend(b"xterm");
    d.extend(80u32.to_be_bytes());
    d.extend(24u32.to_be_bytes());
    d.extend(0u32.to_be_bytes());
    d.extend(0u32.to_be_bytes());
    let modes: &[(u8, u32)] = &[(3, 127), (42, 1), (128, 38400), (129, 38400)];
    let mut m = Vec::new();
    for (op, v) in modes {
        m.push(*op);
        m.extend(v.to_be_bytes());
    }
    m.push(0);
    d.extend((m.len() as u32).to_be_bytes());
    d.extend(m);
    d
}

#[test]
fn a_channel_request_keeps_its_type_specific_data_byte_for_byte() {
    let data = putty_pty_req_data();
    let mut payload = vec![98, 0, 0, 0, 7, 0, 0, 0, 7];
    payload.extend(b"pty-req");
    payload.push(1);
    payload.extend(&data);
    let Message::ChannelRequest(r) = Message::decode(&payload).unwrap() else {
        panic!("not a channel request");
    };
    assert_eq!(
        (r.recipient, r.kind.to_str(), r.want_reply),
        (7, Some("pty-req"), true)
    );
    assert_eq!(r.data, data);
    assert_eq!(Message::ChannelRequest(r).encode(), payload);
}

#[test]
fn a_channel_open_layout_matches_rfc_4254() {
    let m = ChannelOpen::new("session".into(), 1, 2, 3, vec![9]);
    let mut expected = vec![90, 0, 0, 0, 7];
    expected.extend(b"session");
    expected.extend([0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 9]);
    assert_eq!(Message::ChannelOpen(m).encode(), expected);
}

#[test]
fn extended_data_layout_matches_rfc_4254() {
    let m = ChannelExtendedData::new(5, 1, b"err".to_vec());
    assert_eq!(
        Message::ChannelExtendedData(m).encode(),
        vec![95, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 3, b'e', b'r', b'r']
    );
}

proptest! {
    #[test]
    fn data_encoded_from_its_parts_is_the_message_encoded(
        recipient in any::<u32>(),
        code in any::<u32>(),
        data in bytes(),
        before in bytes(),
    ) {
        let mut out = before.clone();
        ChannelData::encode_from(recipient, &data, &mut out);
        let message = Message::ChannelData(ChannelData::new(recipient, data.clone())).encode();
        prop_assert_eq!(out, [before.clone(), message].concat());
        let mut out = before.clone();
        ChannelExtendedData::encode_from(recipient, code, &data, &mut out);
        let message = Message::ChannelExtendedData(ChannelExtendedData::new(recipient, code, data)).encode();
        prop_assert_eq!(out, [before, message].concat());
    }
}
