use justssh_wire::{ChannelOpen, ChannelRequest, GlobalRequest, Message, Name};
use proptest::prelude::*;

/// A name that is not UTF-8: a lone continuation byte and a Latin-1 `é`.
const NOT_UTF8: &[u8] = b"x\x80\xe9@y";

#[test]
fn names_that_are_not_utf8_decode_and_encode_back_byte_for_byte() {
    let mut global = vec![80, 0, 0, 0, 5];
    global.extend(NOT_UTF8);
    global.extend([1, 7]);
    let mut open = vec![90, 0, 0, 0, 5];
    open.extend(NOT_UTF8);
    open.extend([0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 9]);
    let mut request = vec![98, 0, 0, 0, 4, 0, 0, 0, 5];
    request.extend(NOT_UTF8);
    request.extend([0, 8]);
    for payload in [global, open, request] {
        let m = Message::decode(&payload).unwrap();
        let kind = match &m {
            Message::GlobalRequest(m) => &m.kind,
            Message::ChannelOpen(m) => &m.kind,
            Message::ChannelRequest(m) => &m.kind,
            other => panic!("{other:?}"),
        };
        assert_eq!(kind.as_bytes(), NOT_UTF8);
        assert_eq!(kind.to_str(), None);
        assert_eq!(m.encode(), payload);
    }
}

#[test]
fn a_name_compares_equal_to_the_text_it_holds() {
    let name = Name::from("exec");
    assert!(name == "exec");
    assert!(name != "exe");
    assert!(name != "exed");
    // `&Name == &str`, as `request.kind() == "exec"` compares.
    assert!(&name == "exec");
    assert!(&name != "exed");
    assert!("exec" == name && "exed" != name);
    assert!("exec" == &name);
    assert!(name == b"exec" && name != b"exed");
    let text = String::from("exec");
    assert!(name == text && text == name);
    assert_eq!(
        match name.to_str() {
            Some("shell" | "exec") => 1,
            _ => 0,
        },
        1
    );
    let mut by_name = std::collections::HashMap::new();
    by_name.insert(name.clone(), 1);
    assert_eq!(by_name.get(&b"exec"[..]), Some(&1));
    assert_eq!(name.to_str(), Some("exec"));
    assert!(Name::from(NOT_UTF8) != "x\u{80}é@y");
}

#[test]
fn a_name_shows_bytes_that_are_not_utf8_escaped() {
    let name = Name::from(NOT_UTF8);
    assert_eq!(format!("{name}"), "x\\x80\\xe9@y");
    assert_eq!(format!("{name:?}"), "\"x\\x80\\xe9@y\"");
    assert_eq!(
        format!("{name:.5}|{:>6}", Name::from("ab")),
        "x\\x80|    ab"
    );
}

proptest! {
    #[test]
    fn any_name_survives_encode_then_decode(
        kind in prop::collection::vec(any::<u8>(), 0..32),
        want_reply in any::<bool>(),
    ) {
        for m in [
            Message::GlobalRequest(GlobalRequest::new(kind.clone().into(), want_reply, vec![1])),
            Message::ChannelOpen(ChannelOpen::new(kind.clone().into(), 1, 2, 3, vec![4])),
            Message::ChannelRequest(ChannelRequest::new(5, kind.clone().into(), want_reply, vec![6])),
        ] {
            prop_assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }
}
