//! Message numbers (RFC 4250 §4.1, RFC 5656 §7.1).

pub const DISCONNECT: u8 = 1;
pub const IGNORE: u8 = 2;
pub const UNIMPLEMENTED: u8 = 3;
pub const DEBUG: u8 = 4;
pub const SERVICE_REQUEST: u8 = 5;
pub const SERVICE_ACCEPT: u8 = 6;
pub const EXT_INFO: u8 = 7;
pub const KEXINIT: u8 = 20;
pub const NEWKEYS: u8 = 21;
pub const KEX_ECDH_INIT: u8 = 30;
pub const KEX_ECDH_REPLY: u8 = 31;
pub const USERAUTH_REQUEST: u8 = 50;
pub const USERAUTH_FAILURE: u8 = 51;
pub const USERAUTH_SUCCESS: u8 = 52;
pub const GLOBAL_REQUEST: u8 = 80;
pub const REQUEST_SUCCESS: u8 = 81;
pub const REQUEST_FAILURE: u8 = 82;
pub const PING: u8 = 192;
pub const PONG: u8 = 193;
pub const CHANNEL_OPEN: u8 = 90;
pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const CHANNEL_OPEN_FAILURE: u8 = 92;
pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const CHANNEL_DATA: u8 = 94;
pub const CHANNEL_EXTENDED_DATA: u8 = 95;
pub const CHANNEL_EOF: u8 = 96;
pub const CHANNEL_CLOSE: u8 = 97;
pub const CHANNEL_REQUEST: u8 = 98;
pub const CHANNEL_SUCCESS: u8 = 99;
pub const CHANNEL_FAILURE: u8 = 100;

/// Whether `n` is a message number this crate decodes.
pub const fn is_known(n: u8) -> bool {
    matches!(
        n,
        DISCONNECT..=EXT_INFO
            | KEXINIT
            | NEWKEYS
            | KEX_ECDH_INIT
            | KEX_ECDH_REPLY
            | USERAUTH_REQUEST..=USERAUTH_SUCCESS
            | GLOBAL_REQUEST..=REQUEST_FAILURE
            | CHANNEL_OPEN..=CHANNEL_FAILURE
            | PING
            | PONG
    )
}
