use justssh_wire::{GlobalRequest, Message, RequestFailure, RequestSuccess, number};
use proptest::prelude::*;

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

fn global_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        ("[a-z0-9@.-]{1,32}", any::<bool>(), bytes())
            .prop_map(|(k, w, d)| Message::GlobalRequest(GlobalRequest::new(k.into(), w, d))),
        bytes().prop_map(|d| Message::RequestSuccess(RequestSuccess::new(d))),
        bytes().prop_map(|d| Message::RequestFailure(RequestFailure::new(d))),
    ]
}

proptest! {
    #[test]
    fn every_global_message_survives_encode_then_decode(m in global_message()) {
        prop_assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }
}

#[test]
fn openssh_keepalive_decodes_as_a_global_request_wanting_a_reply() {
    // clientloop.c server_alive_check: string "keepalive@openssh.com", bool 1.
    let mut payload = vec![80, 0, 0, 0, 21];
    payload.extend(b"keepalive@openssh.com");
    payload.push(1);
    assert_eq!(
        Message::decode(&payload).unwrap(),
        Message::GlobalRequest(GlobalRequest::new(
            "keepalive@openssh.com".into(),
            true,
            Vec::new()
        ))
    );
}

#[test]
fn a_success_carries_its_payload_unparsed() {
    // tcpip-forward with port 0: uint32 port bound.
    let payload = [81, 0, 0, 0x9c, 0x40];
    assert_eq!(
        Message::decode(&payload).unwrap(),
        Message::RequestSuccess(RequestSuccess::new(vec![0, 0, 0x9c, 0x40]))
    );
}

#[test]
fn every_known_number_has_a_decoder_and_no_other_does() {
    for n in 0..=u8::MAX {
        let unknown = matches!(Message::decode(&[n]), Ok(Message::Unknown(_)));
        assert_eq!(number::is_known(n), !unknown, "message number {n}");
    }
}
