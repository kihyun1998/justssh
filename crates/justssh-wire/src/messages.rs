//! Transport-layer messages: RFC 4253 and the ECDH exchange of RFC 5656 §4.

use crate::codec::{DecodeError, Reader, Writer};
use crate::number;

/// `SSH_MSG_KEXINIT` (RFC 4253 §7.1).
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KexInit {
    /// 16 random bytes.
    pub cookie: [u8; 16],
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
    pub reserved: u32,
}

/// `SSH_MSG_KEX_ECDH_INIT`: the client's ephemeral public key `Q_C`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KexEcdhInit {
    pub q_c: Vec<u8>,
}

/// `SSH_MSG_KEX_ECDH_REPLY`: the server's host key `K_S`, ephemeral public key `Q_S` and
/// the signature over the exchange hash.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KexEcdhReply {
    pub host_key: Vec<u8>,
    pub q_s: Vec<u8>,
    pub signature: Vec<u8>,
}

/// `SSH_MSG_NEWKEYS`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewKeys;

/// `SSH_MSG_SERVICE_REQUEST`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceRequest {
    pub service: String,
}

/// `SSH_MSG_SERVICE_ACCEPT`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceAccept {
    pub service: String,
}

/// `SSH_MSG_DISCONNECT`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Disconnect {
    pub reason: u32,
    pub description: String,
    pub language: String,
}

/// `SSH_MSG_IGNORE`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ignore {
    pub data: Vec<u8>,
}

/// `SSH_MSG_DEBUG`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Debug {
    pub always_display: bool,
    pub message: String,
    pub language: String,
}

/// `SSH_MSG_UNIMPLEMENTED`: the sequence number of the packet that was not understood.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unimplemented {
    pub sequence_number: u32,
}

impl KexEcdhInit {
    pub fn new(q_c: Vec<u8>) -> Self {
        KexEcdhInit { q_c }
    }
}

impl KexEcdhReply {
    pub fn new(host_key: Vec<u8>, q_s: Vec<u8>, signature: Vec<u8>) -> Self {
        KexEcdhReply {
            host_key,
            q_s,
            signature,
        }
    }
}

impl ServiceRequest {
    pub fn new(service: impl Into<String>) -> Self {
        ServiceRequest {
            service: service.into(),
        }
    }
}

impl ServiceAccept {
    pub fn new(service: impl Into<String>) -> Self {
        ServiceAccept {
            service: service.into(),
        }
    }
}

impl Disconnect {
    pub fn new(reason: u32, description: impl Into<String>, language: impl Into<String>) -> Self {
        Disconnect {
            reason,
            description: description.into(),
            language: language.into(),
        }
    }
}

impl Ignore {
    pub fn new(data: Vec<u8>) -> Self {
        Ignore { data }
    }
}

impl Debug {
    pub fn new(
        always_display: bool,
        message: impl Into<String>,
        language: impl Into<String>,
    ) -> Self {
        Debug {
            always_display,
            message: message.into(),
            language: language.into(),
        }
    }
}

impl Unimplemented {
    pub fn new(sequence_number: u32) -> Self {
        Unimplemented { sequence_number }
    }
}

/// A transport message, or the number of one this crate does not decode.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    KexInit(KexInit),
    KexEcdhInit(KexEcdhInit),
    KexEcdhReply(KexEcdhReply),
    NewKeys(NewKeys),
    ServiceRequest(ServiceRequest),
    ServiceAccept(ServiceAccept),
    Disconnect(Disconnect),
    Ignore(Ignore),
    Debug(Debug),
    Unimplemented(Unimplemented),
    ExtInfo(ExtInfo),
    UserauthRequest(UserauthRequest),
    UserauthFailure(UserauthFailure),
    UserauthSuccess(UserauthSuccess),
    Ping(Ping),
    Pong(Pong),
    /// A message number this crate has no decoder for; its body is not read.
    Unknown(u8),
}

impl Message {
    /// The payload: message number followed by the fields.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Message::KexInit(m) => {
                w.u8(number::KEXINIT)
                    .bytes(&m.cookie)
                    .name_list(&m.kex_algorithms)
                    .name_list(&m.server_host_key_algorithms)
                    .name_list(&m.encryption_algorithms_client_to_server)
                    .name_list(&m.encryption_algorithms_server_to_client)
                    .name_list(&m.mac_algorithms_client_to_server)
                    .name_list(&m.mac_algorithms_server_to_client)
                    .name_list(&m.compression_algorithms_client_to_server)
                    .name_list(&m.compression_algorithms_server_to_client)
                    .name_list(&m.languages_client_to_server)
                    .name_list(&m.languages_server_to_client)
                    .bool(m.first_kex_packet_follows)
                    .u32(m.reserved);
            }
            Message::KexEcdhInit(m) => {
                w.u8(number::KEX_ECDH_INIT).string(&m.q_c);
            }
            Message::KexEcdhReply(m) => {
                w.u8(number::KEX_ECDH_REPLY)
                    .string(&m.host_key)
                    .string(&m.q_s)
                    .string(&m.signature);
            }
            Message::NewKeys(_) => {
                w.u8(number::NEWKEYS);
            }
            Message::ServiceRequest(m) => {
                w.u8(number::SERVICE_REQUEST).string(m.service.as_bytes());
            }
            Message::ServiceAccept(m) => {
                w.u8(number::SERVICE_ACCEPT).string(m.service.as_bytes());
            }
            Message::Disconnect(m) => {
                w.u8(number::DISCONNECT)
                    .u32(m.reason)
                    .string(m.description.as_bytes())
                    .string(m.language.as_bytes());
            }
            Message::Ignore(m) => {
                w.u8(number::IGNORE).string(&m.data);
            }
            Message::Debug(m) => {
                w.u8(number::DEBUG)
                    .bool(m.always_display)
                    .string(m.message.as_bytes())
                    .string(m.language.as_bytes());
            }
            Message::Unimplemented(m) => {
                w.u8(number::UNIMPLEMENTED).u32(m.sequence_number);
            }
            Message::ExtInfo(m) => {
                let count =
                    u32::try_from(m.extensions.len()).expect("more than u32::MAX extensions");
                w.u8(number::EXT_INFO).u32(count);
                for (name, value) in &m.extensions {
                    w.string(name.as_bytes()).string(value);
                }
            }
            Message::UserauthRequest(m) => {
                w.u8(number::USERAUTH_REQUEST)
                    .string(&m.user)
                    .string(m.service.as_bytes())
                    .string(m.method.as_bytes())
                    .bytes(&m.method_data);
            }
            Message::UserauthFailure(m) => {
                w.u8(number::USERAUTH_FAILURE)
                    .name_list(&m.methods)
                    .bool(m.partial_success);
            }
            Message::UserauthSuccess(_) => {
                w.u8(number::USERAUTH_SUCCESS);
            }
            Message::Ping(m) => {
                w.u8(number::PING).string(&m.data);
            }
            Message::Pong(m) => {
                w.u8(number::PONG).string(&m.data);
            }
            Message::Unknown(n) => {
                w.u8(*n);
            }
        }
        w.into_bytes()
    }

    /// Decodes a whole payload. Every field must be present and no byte may be left over,
    /// except for [`Message::Unknown`], whose body is not read.
    pub fn decode(payload: &[u8]) -> Result<Message, DecodeError> {
        let (&n, body) = payload.split_first().ok_or(DecodeError::Empty)?;
        let mut r = Reader::new(body);
        let m = match n {
            number::KEXINIT => {
                let mut cookie = [0u8; 16];
                cookie.copy_from_slice(r.bytes(16)?);
                Message::KexInit(KexInit {
                    cookie,
                    kex_algorithms: r.name_list()?,
                    server_host_key_algorithms: r.name_list()?,
                    encryption_algorithms_client_to_server: r.name_list()?,
                    encryption_algorithms_server_to_client: r.name_list()?,
                    mac_algorithms_client_to_server: r.name_list()?,
                    mac_algorithms_server_to_client: r.name_list()?,
                    compression_algorithms_client_to_server: r.name_list()?,
                    compression_algorithms_server_to_client: r.name_list()?,
                    languages_client_to_server: r.name_list()?,
                    languages_server_to_client: r.name_list()?,
                    first_kex_packet_follows: r.bool()?,
                    reserved: r.u32()?,
                })
            }
            number::KEX_ECDH_INIT => Message::KexEcdhInit(KexEcdhInit::new(r.string()?.to_vec())),
            number::KEX_ECDH_REPLY => Message::KexEcdhReply(KexEcdhReply::new(
                r.string()?.to_vec(),
                r.string()?.to_vec(),
                r.string()?.to_vec(),
            )),
            number::NEWKEYS => Message::NewKeys(NewKeys),
            number::SERVICE_REQUEST => Message::ServiceRequest(ServiceRequest::new(r.utf8()?)),
            number::SERVICE_ACCEPT => Message::ServiceAccept(ServiceAccept::new(r.utf8()?)),
            number::DISCONNECT => {
                let reason = r.u32()?;
                let description = String::from_utf8_lossy(r.string()?).into_owned();
                let language = String::from_utf8_lossy(r.string()?).into_owned();
                Message::Disconnect(Disconnect {
                    reason,
                    description,
                    language,
                })
            }
            number::IGNORE => Message::Ignore(Ignore::new(r.string()?.to_vec())),
            number::DEBUG => {
                let always_display = r.bool()?;
                let message = String::from_utf8_lossy(r.string()?).into_owned();
                let language = String::from_utf8_lossy(r.string()?).into_owned();
                Message::Debug(Debug {
                    always_display,
                    message,
                    language,
                })
            }
            number::UNIMPLEMENTED => Message::Unimplemented(Unimplemented::new(r.u32()?)),
            number::EXT_INFO => {
                let count = r.u32()?;
                let mut extensions = Vec::new();
                for _ in 0..count {
                    let name = r.utf8()?.to_owned();
                    extensions.push((name, r.string()?.to_vec()));
                }
                Message::ExtInfo(ExtInfo { extensions })
            }
            number::USERAUTH_REQUEST => {
                let user = r.string()?.to_vec();
                let service = r.utf8()?.to_owned();
                let method = r.utf8()?.to_owned();
                let method_data = r.remaining().to_vec();
                return Ok(Message::UserauthRequest(UserauthRequest {
                    user,
                    service,
                    method,
                    method_data,
                }));
            }
            number::USERAUTH_FAILURE => Message::UserauthFailure(UserauthFailure {
                methods: r.name_list()?,
                partial_success: r.bool()?,
            }),
            number::USERAUTH_SUCCESS => Message::UserauthSuccess(UserauthSuccess),
            number::PING => Message::Ping(Ping::new(r.string()?.to_vec())),
            number::PONG => Message::Pong(Pong::new(r.string()?.to_vec())),
            other => return Ok(Message::Unknown(other)),
        };
        r.finish()?;
        Ok(m)
    }
}

/// `SSH_MSG_EXT_INFO` (RFC 8308 §2.3): extension names and their values.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtInfo {
    pub extensions: Vec<(String, Vec<u8>)>,
}

impl ExtInfo {
    pub fn new(extensions: Vec<(String, Vec<u8>)>) -> Self {
        ExtInfo { extensions }
    }
}

/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 §5). `method_data` is everything after the method
/// name, left undecoded; it can hold a password, so `Debug` shows only its length.
#[non_exhaustive]
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UserauthRequest {
    /// The user name as sent; RFC 4252 calls for UTF-8, but nothing on the wire enforces it.
    pub user: Vec<u8>,
    pub service: String,
    pub method: String,
    pub method_data: Vec<u8>,
}

impl core::fmt::Debug for UserauthRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserauthRequest")
            .field("user", &String::from_utf8_lossy(&self.user))
            .field("service", &self.service)
            .field("method", &self.method)
            .field("method_data_len", &self.method_data.len())
            .finish()
    }
}

impl UserauthRequest {
    pub fn new(
        user: Vec<u8>,
        service: impl Into<String>,
        method: impl Into<String>,
        method_data: Vec<u8>,
    ) -> Self {
        UserauthRequest {
            user,
            service: service.into(),
            method: method.into(),
            method_data,
        }
    }
}

/// `SSH_MSG_USERAUTH_FAILURE`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserauthFailure {
    /// Methods that may continue.
    pub methods: Vec<String>,
    pub partial_success: bool,
}

impl UserauthFailure {
    pub fn new(methods: Vec<String>, partial_success: bool) -> Self {
        UserauthFailure {
            methods,
            partial_success,
        }
    }
}

/// `SSH_MSG_USERAUTH_SUCCESS`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserauthSuccess;

/// `SSH2_MSG_PING` (OpenSSH PROTOCOL §1.8).
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ping {
    pub data: Vec<u8>,
}

impl Ping {
    pub fn new(data: Vec<u8>) -> Self {
        Ping { data }
    }
}

/// `SSH2_MSG_PONG`: the data of the `SSH2_MSG_PING` it answers.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pong {
    pub data: Vec<u8>,
}

impl Pong {
    pub fn new(data: Vec<u8>) -> Self {
        Pong { data }
    }
}
