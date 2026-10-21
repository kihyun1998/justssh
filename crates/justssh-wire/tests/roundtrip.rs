use justssh_wire::{
    Debug, Disconnect, Ignore, KexEcdhInit, KexEcdhReply, KexInit, Message, NewKeys, ServiceAccept,
    ServiceRequest, Unimplemented,
};
use proptest::prelude::*;

fn name() -> impl Strategy<Value = String> {
    "[a-z0-9@.-]{1,24}"
}

fn names() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(name(), 0..6)
}

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..96)
}

fn kexinit() -> impl Strategy<Value = KexInit> {
    (
        any::<[u8; 16]>(),
        prop::collection::vec(names(), 10),
        any::<bool>(),
        any::<u32>(),
    )
        .prop_map(|(cookie, lists, follows, reserved)| {
            let mut m = KexInit::default();
            m.cookie = cookie;
            m.kex_algorithms = lists[0].clone();
            m.server_host_key_algorithms = lists[1].clone();
            m.encryption_algorithms_client_to_server = lists[2].clone();
            m.encryption_algorithms_server_to_client = lists[3].clone();
            m.mac_algorithms_client_to_server = lists[4].clone();
            m.mac_algorithms_server_to_client = lists[5].clone();
            m.compression_algorithms_client_to_server = lists[6].clone();
            m.compression_algorithms_server_to_client = lists[7].clone();
            m.languages_client_to_server = lists[8].clone();
            m.languages_server_to_client = lists[9].clone();
            m.first_kex_packet_follows = follows;
            m.reserved = reserved;
            m
        })
}

fn message() -> impl Strategy<Value = Message> {
    prop_oneof![
        kexinit().prop_map(Message::KexInit),
        bytes().prop_map(|q| Message::KexEcdhInit(KexEcdhInit::new(q))),
        (bytes(), bytes(), bytes())
            .prop_map(|(k, q, s)| Message::KexEcdhReply(KexEcdhReply::new(k, q, s))),
        Just(Message::NewKeys(NewKeys::default())),
        name().prop_map(|n| Message::ServiceRequest(ServiceRequest::new(n))),
        name().prop_map(|n| Message::ServiceAccept(ServiceAccept::new(n))),
        (any::<u32>(), ".{0,40}", "[a-z-]{0,8}")
            .prop_map(|(r, d, l)| Message::Disconnect(Disconnect::new(r, d, l))),
        bytes().prop_map(|d| Message::Ignore(Ignore::new(d))),
        (any::<bool>(), ".{0,40}", "[a-z-]{0,8}")
            .prop_map(|(a, m, l)| Message::Debug(Debug::new(a, m, l))),
        any::<u32>().prop_map(|s| Message::Unimplemented(Unimplemented::new(s))),
    ]
}

proptest! {
    #[test]
    fn every_message_survives_encode_then_decode(m in message()) {
        let payload = m.encode();
        prop_assert_eq!(Message::decode(&payload).unwrap(), m);
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(b in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Message::decode(&b);
    }
}

#[test]
fn kexinit_wire_layout_matches_rfc_4253() {
    let mut m = KexInit::default();
    m.cookie = [0xAA; 16];
    m.kex_algorithms = vec!["k".into(), "x".into()];
    m.server_host_key_algorithms = vec!["h".into()];
    m.encryption_algorithms_client_to_server = vec!["c".into()];
    m.encryption_algorithms_server_to_client = vec!["s".into()];
    m.mac_algorithms_client_to_server = vec!["m".into()];
    m.mac_algorithms_server_to_client = vec!["n".into()];
    m.compression_algorithms_client_to_server = vec!["z".into()];
    m.compression_algorithms_server_to_client = vec!["y".into()];
    m.languages_client_to_server = vec!["l".into()];
    m.languages_server_to_client = vec![];
    m.first_kex_packet_follows = true;
    m.reserved = 7;
    let mut expected = vec![20u8];
    expected.extend([0xAA; 16]);
    expected.extend([0, 0, 0, 3, b'k', b',', b'x']);
    for c in *b"hcsmnzyl" {
        expected.extend([0, 0, 0, 1, c]);
    }
    expected.extend([0, 0, 0, 0]);
    expected.push(1);
    expected.extend([0, 0, 0, 7]);
    assert_eq!(Message::KexInit(m).encode(), expected);
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut payload = Message::NewKeys(NewKeys::default()).encode();
    payload.push(0);
    assert!(Message::decode(&payload).is_err());
}

#[test]
fn unknown_message_number_decodes_as_unknown() {
    assert_eq!(
        Message::decode(&[200, 1, 2]).unwrap(),
        Message::Unknown(200)
    );
}
