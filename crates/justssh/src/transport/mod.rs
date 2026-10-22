//! The transport layer (RFC 4253) for either role: version exchange, key exchange, the binary
//! packet protocol and the `ssh-userauth` service request.

mod allowed;
mod kex;
mod negotiate;
mod packet;
mod userauth;
mod version;

use justssh_wire::{
    Disconnect, ExtInfo, KexEcdhInit, KexEcdhReply, KexInit, Message, NewKeys, Pong, ServiceAccept,
    ServiceRequest, Unimplemented, UserauthFailure, UserauthSuccess, number,
};
use zeroize::Zeroizing;

use crate::config::{BoxRng, HostKey};
use crate::connection::{ChannelId, ChannelInfo, Channels, Step};
use crate::event::{Action, Closed, DisconnectReason, Error, Event, PasswordRequest, Phase};
use crate::handshake::{Handshake, KexInitRecord};
use crate::key::PrivateKey;

use allowed::{Stage, Verdict};
use packet::{Cipher, OpenError};
pub(crate) use userauth::Method;
use userauth::{AfterFailure, ClientAuth, KeyAttempt, ServerAuth};
use version::{Line, VersionError};

const USERAUTH: &str = "ssh-userauth";

/// Most input held unprocessed while a verdict is pending: one largest packet with its length
/// field and MAC.
const PENDING_INPUT: usize = packet::MAX_PACKET + 4 + packet::MAX_MAC;

/// The `server-sig-algs` value sent in `SSH_MSG_EXT_INFO`: x/crypto/ssh's default public key
/// authentication algorithms, in its order.
const SERVER_SIG_ALGS: &str = "ssh-ed25519,sk-ssh-ed25519@openssh.com,\
    sk-ecdsa-sha2-nistp256@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
    ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,ssh-rsa,ssh-dss";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Server,
    Client,
}

/// A client's key exchange waiting for the consumer's host key verdict.
struct PendingKex {
    k: Zeroizing<Vec<u8>>,
    h: Vec<u8>,
}

/// The algorithm lists a side offers, and whether it offers strict KEX; other than the defaults
/// only under `test-support`.
#[derive(Clone)]
pub(crate) struct Preference {
    kex: Vec<String>,
    host_key: Vec<String>,
    cipher: Vec<String>,
    mac: Vec<String>,
    /// The server-to-client lists, where they differ from `cipher` and `mac`.
    server_to_client: Option<(Vec<String>, Vec<String>)>,
    pub(crate) strict_kex: bool,
}

fn names(l: &[&str]) -> Vec<String> {
    l.iter().map(|s| (*s).to_owned()).collect()
}

impl Default for Preference {
    fn default() -> Self {
        Preference {
            kex: names(negotiate::KEX),
            host_key: names(negotiate::HOST_KEY),
            cipher: names(negotiate::CIPHER),
            mac: names(negotiate::MAC),
            server_to_client: None,
            strict_kex: true,
        }
    }
}

impl Preference {
    /// Offers only `kex`, `ciphers` and `macs`, in that order.
    #[cfg(feature = "test-support")]
    pub(crate) fn set_lists(&mut self, kex: &[&str], ciphers: &[&str], macs: &[&str]) {
        self.kex = names(kex);
        self.cipher = names(ciphers);
        self.mac = names(macs);
    }

    /// Offers only `algorithms` as host key algorithms (a client's).
    #[cfg(feature = "test-support")]
    pub(crate) fn set_host_keys(&mut self, algorithms: &[&str]) {
        self.host_key = names(algorithms);
    }

    /// Offers `ciphers` and `macs` for the server-to-client direction only.
    #[cfg(feature = "test-support")]
    pub(crate) fn set_server_to_client(&mut self, ciphers: &[&str], macs: &[&str]) {
        self.server_to_client = Some((names(ciphers), names(macs)));
    }
}

/// Key exchange state that lives only until `SSH_MSG_NEWKEYS`.
struct Exchange {
    /// The client's secret and its public value as hashed.
    client: Option<(kex::ClientSecret, Vec<u8>)>,
    /// Keys for the incoming direction, taken into use on the peer's `SSH_MSG_NEWKEYS`.
    incoming: Option<Cipher>,
}

pub(crate) struct Transport {
    role: Role,
    /// A server's host keys, in the order offered; none for a client.
    host_keys: Vec<HostKey>,
    rng: BoxRng,
    started: bool,
    phase: Phase,
    stage: Stage,
    version_done: bool,
    version_budget: usize,
    inbuf: Vec<u8>,
    handshake: Handshake,
    in_seq: u32,
    out_seq: u32,
    /// Packets received and sent under the keys now in use; a sequence number may not repeat
    /// under one key.
    in_since_keys: u64,
    out_since_keys: u64,
    opening: Cipher,
    sealing: Cipher,
    packets_received: u64,
    first_kex_done: bool,
    skip_next: bool,
    exchange: Option<Exchange>,
    session_id: Option<Vec<u8>>,
    peer_host_key: Option<Vec<u8>>,
    /// The server's authentication state; `None` for a client.
    auth: Option<ServerAuth>,
    /// The client's authentication state; `None` for a server.
    client_auth: Option<ClientAuth>,
    host_key_pending: Option<PendingKex>,
    /// Whether a server answers `ext-info-c` with `SSH_MSG_EXT_INFO`.
    send_ext_info: bool,
    preference: Option<Preference>,
    /// The extensions of the server's first `SSH_MSG_EXT_INFO`, received by a client.
    ext_info: Option<Vec<(String, Vec<u8>)>>,
    channels: Channels,
    #[cfg(feature = "test-support")]
    raw_receive: bool,
    actions: Vec<Action>,
}

impl Transport {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        role: Role,
        host_keys: Vec<HostKey>,
        client_user: Option<Vec<u8>>,
        rng: BoxRng,
        local_version: String,
        max_auth_tries: u32,
        channel_window: u32,
        channel_max_packet: u32,
    ) -> Self {
        Transport {
            role,
            host_keys,
            rng,
            started: false,
            phase: Phase::Handshake,
            stage: Stage::KexInit,
            version_done: false,
            version_budget: version::MAX_TOTAL,
            inbuf: Vec::new(),
            handshake: Handshake {
                local_version,
                peer_version: None,
                local_kexinit: None,
                peer_kexinit: None,
                negotiated: None,
            },
            in_seq: 0,
            out_seq: 0,
            in_since_keys: 0,
            out_since_keys: 0,
            opening: Cipher::Plain,
            sealing: Cipher::Plain,
            packets_received: 0,
            first_kex_done: false,
            skip_next: false,
            exchange: None,
            session_id: None,
            peer_host_key: None,
            auth: (role == Role::Server).then(|| ServerAuth::new(max_auth_tries)),
            client_auth: client_user.map(ClientAuth::new),
            host_key_pending: None,
            send_ext_info: true,
            preference: None,
            ext_info: None,
            channels: Channels::new(channel_window, channel_max_packet),
            #[cfg(feature = "test-support")]
            raw_receive: false,
            actions: Vec::new(),
        }
    }

    /// Sends `payload` as one packet, whatever it holds.
    #[cfg(feature = "test-support")]
    pub(crate) fn send_raw(&mut self, payload: &[u8]) -> Vec<Action> {
        self.send_payload(payload);
        std::mem::take(&mut self.actions)
    }

    /// After the first key exchange, hands every received payload over as
    /// [`Action::RawReceived`] instead of handling it.
    #[cfg(feature = "test-support")]
    pub(crate) fn set_raw_receive(&mut self, raw: bool) {
        self.raw_receive = raw;
    }

    pub(crate) fn set_send_ext_info(&mut self, send: bool) {
        self.send_ext_info = send;
    }

    pub(crate) fn set_preference(&mut self, preference: Option<Preference>) {
        self.preference = preference;
    }

    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }

    pub(crate) fn handshake(&self) -> &Handshake {
        &self.handshake
    }

    pub(crate) fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_deref()
    }

    pub(crate) fn peer_host_key(&self) -> Option<&[u8]> {
        self.peer_host_key.as_deref()
    }

    /// The names in the server's `server-sig-algs` extension, if it sent one.
    pub(crate) fn server_sig_algs(&self) -> Option<Vec<&str>> {
        let value = core::str::from_utf8(self.ext_info("server-sig-algs")?).ok()?;
        Some(value.split(',').filter(|n| !n.is_empty()).collect())
    }

    pub(crate) fn ext_info(&self, name: &str) -> Option<&[u8]> {
        self.ext_info
            .as_ref()?
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    pub(crate) fn process(&mut self, event: Event<'_>) -> Vec<Action> {
        if self.phase == Phase::Closed {
            return Vec::new();
        }
        match event {
            Event::Connected if !self.started => {
                self.started = true;
                let line = format!("{}\r\n", self.handshake.local_version);
                self.write(line.into_bytes());
            }
            Event::Received(bytes) if self.started => {
                self.inbuf.extend_from_slice(bytes);
                if self.waiting() && self.inbuf.len() > PENDING_INPUT {
                    self.fail(DisconnectReason::PROTOCOL_ERROR, Error::InputOverflow);
                } else {
                    self.drain();
                }
            }
            Event::AuthAccepted if self.auth_pending() => {
                self.end_pending();
                self.send(&Message::UserauthSuccess(UserauthSuccess::default()));
                self.stage = Stage::Connected;
                self.phase = Phase::Connected;
                self.drain();
            }
            Event::AuthRejected if self.auth_pending() => {
                self.end_pending();
                self.auth_failed("password");
                self.drain();
            }
            Event::HostKeyAccepted if self.host_key_pending.is_some() => {
                let pending = self.host_key_pending.take().expect("checked");
                self.finish_exchange(&pending.k, &pending.h);
                self.drain();
            }
            Event::HostKeyRejected if self.host_key_pending.is_some() => {
                self.host_key_pending = None;
                self.fail(
                    DisconnectReason::HOST_KEY_NOT_VERIFIABLE,
                    Error::HostKeyRejected,
                );
            }
            Event::DeadlineExceeded if self.started => {
                self.fail(DisconnectReason::BY_APPLICATION, Error::DeadlineExceeded)
            }
            _ => self.fail(DisconnectReason::PROTOCOL_ERROR, Error::UnexpectedEvent),
        }
        std::mem::take(&mut self.actions)
    }

    /// Carries out what the channel table asked for, stopping at a failure.
    fn run(&mut self, steps: Vec<Step>) {
        for step in steps {
            match step {
                Step::Send(m) => self.send(&m),
                Step::Emit(a) => self.actions.push(a),
                Step::Fail(reason, error) => return self.fail(reason, error),
            }
        }
    }

    /// Applies a consumer command to the channels; nothing happens before the connection is
    /// authenticated or after it has closed.
    pub(crate) fn channels(
        &mut self,
        command: impl FnOnce(&mut Channels) -> Vec<Step>,
    ) -> Vec<Action> {
        if self.phase == Phase::Connected {
            let steps = command(&mut self.channels);
            self.run(steps);
        }
        std::mem::take(&mut self.actions)
    }

    /// [`channels`](Self::channels) for a command that also returns a value; before the
    /// connection is authenticated nothing happens and the value is its default.
    pub(crate) fn channels_with<T: Default>(
        &mut self,
        command: impl FnOnce(&mut Channels) -> (T, Vec<Step>),
    ) -> (T, Vec<Action>) {
        let mut value = T::default();
        if self.phase == Phase::Connected {
            let (v, steps) = command(&mut self.channels);
            value = v;
            self.run(steps);
        }
        (value, std::mem::take(&mut self.actions))
    }

    pub(crate) fn channel_info(&self, id: ChannelId) -> Option<ChannelInfo> {
        self.channels.info(id)
    }

    fn auth_pending(&self) -> bool {
        self.auth.as_ref().is_some_and(|a| a.pending)
    }

    /// Whether received input waits for a verdict from the consumer.
    fn waiting(&self) -> bool {
        self.auth_pending() || self.host_key_pending.is_some()
    }

    /// Sends a client authentication request for `method`.
    pub(crate) fn client_attempt(&mut self, method: Method, password: &[u8]) -> Vec<Action> {
        if self.phase == Phase::Closed {
            return Vec::new();
        }
        let stage = self.stage;
        let Some(auth) = self
            .client_auth
            .as_mut()
            .filter(|a| a.attempt.is_none() && stage == Stage::Auth)
        else {
            self.fail(DisconnectReason::PROTOCOL_ERROR, Error::UnexpectedEvent);
            return std::mem::take(&mut self.actions);
        };
        auth.attempt = Some(method);
        auth.ext_info = false;
        let payload = userauth::client_request(&auth.user, method, password);
        self.send_payload(&payload);
        std::mem::take(&mut self.actions)
    }

    /// Sends a `publickey` query for `key` under `algorithm`, or the algorithm the server's
    /// `server-sig-algs` leads to; the signed request follows the server's `PK_OK`.
    pub(crate) fn client_publickey(
        &mut self,
        key: &PrivateKey,
        algorithm: Option<&str>,
    ) -> Vec<Action> {
        if self.phase == Phase::Closed {
            return Vec::new();
        }
        let algorithm = match algorithm {
            None => Some(key.algorithm_for(self.server_sig_algs().as_deref())),
            Some(a) => key.algorithms().iter().find(|k| **k == a).copied(),
        };
        let stage = self.stage;
        let (Some(algorithm), Some(auth)) = (
            algorithm,
            self.client_auth
                .as_mut()
                .filter(|a| a.attempt.is_none() && stage == Stage::Auth),
        ) else {
            self.fail(DisconnectReason::PROTOCOL_ERROR, Error::UnexpectedEvent);
            return std::mem::take(&mut self.actions);
        };
        auth.attempt = Some(Method::PublicKey);
        auth.ext_info = false;
        let payload = userauth::publickey_request(&auth.user, algorithm, &key.public_blob(), None);
        auth.key = Some(KeyAttempt {
            key: key.clone(),
            algorithm,
            signed: false,
        });
        self.send_payload(&payload);
        std::mem::take(&mut self.actions)
    }

    /// Answers the outstanding keyboard-interactive questions.
    pub(crate) fn answer_prompts(&mut self, answers: &[Zeroizing<Vec<u8>>]) -> Vec<Action> {
        if self.phase == Phase::Closed {
            return Vec::new();
        }
        let Some(auth) = self
            .client_auth
            .as_mut()
            .filter(|a| a.questions == Some(answers.len()))
        else {
            self.fail(DisconnectReason::PROTOCOL_ERROR, Error::UnexpectedEvent);
            return std::mem::take(&mut self.actions);
        };
        auth.questions = None;
        let payload = userauth::info_response(answers);
        self.send_payload(&payload);
        std::mem::take(&mut self.actions)
    }

    fn end_pending(&mut self) {
        if let Some(a) = self.auth.as_mut() {
            a.pending = false;
        }
    }

    pub(crate) fn disconnect(
        &mut self,
        reason: DisconnectReason,
        description: &str,
    ) -> Vec<Action> {
        if self.phase != Phase::Closed && self.started {
            self.send(&Message::Disconnect(Disconnect::new(
                reason.code(),
                description,
                "",
            )));
            let phase = self.phase;
            self.close(Closed::Requested { reason, phase });
        }
        std::mem::take(&mut self.actions)
    }

    fn write(&mut self, bytes: Vec<u8>) {
        self.actions.push(Action::Write(bytes));
    }

    fn send(&mut self, message: &Message) {
        self.send_payload(&message.encode());
    }

    fn send_payload(&mut self, payload: &[u8]) {
        if self.out_since_keys > u64::from(u32::MAX) {
            if self.phase != Phase::Closed {
                self.close(Closed::Local {
                    reason: DisconnectReason::PROTOCOL_ERROR,
                    error: Error::SequenceWrap,
                    phase: self.phase,
                });
            }
            return;
        }
        let packet = self.sealing.seal(payload, self.out_seq, &mut *self.rng);
        self.out_seq = self.out_seq.wrapping_add(1);
        self.out_since_keys += 1;
        self.write(packet);
    }

    fn close(&mut self, closed: Closed) {
        self.phase = Phase::Closed;
        self.actions.push(Action::Closed(closed));
    }

    /// Ends the connection because of `error`, telling the peer first when the stream is open.
    fn fail(&mut self, reason: DisconnectReason, error: Error) {
        if self.phase == Phase::Closed {
            return;
        }
        if self.started {
            let description = error.to_string();
            self.send(&Message::Disconnect(Disconnect::new(
                reason.code(),
                description,
                "",
            )));
        }
        let phase = self.phase;
        self.close(Closed::Local {
            reason,
            error,
            phase,
        });
    }

    fn drain(&mut self) {
        let mut consumed = 0;
        self.drain_from(&mut consumed);
        self.inbuf.drain(..consumed);
    }

    /// Handles everything complete in `inbuf[*consumed..]`, advancing `consumed` past it.
    fn drain_from(&mut self, consumed: &mut usize) {
        while self.phase != Phase::Closed && !self.waiting() {
            if !self.version_done {
                match version::take_line(&mut self.inbuf, &mut self.version_budget) {
                    Ok(Line::Incomplete) => return,
                    Ok(Line::Other) => continue,
                    Ok(Line::Version(v)) => self.on_version(v),
                    Err(VersionError::TooLong) => {
                        self.fail(DisconnectReason::PROTOCOL_ERROR, Error::BadVersion)
                    }
                    Err(VersionError::Unsupported) => self.fail(
                        DisconnectReason::PROTOCOL_VERSION_NOT_SUPPORTED,
                        Error::BadVersion,
                    ),
                }
                continue;
            }
            let opened = match self.opening.open(&self.inbuf[*consumed..], self.in_seq) {
                Ok(Some(opened)) => opened,
                Ok(None) => return,
                Err(OpenError::Malformed) => {
                    return self.fail(DisconnectReason::PROTOCOL_ERROR, Error::MalformedPacket);
                }
                Err(OpenError::Mac) => {
                    return self.fail(DisconnectReason::MAC_ERROR, Error::MacMismatch);
                }
            };
            *consumed += opened.used;
            let seq = self.in_seq;
            self.in_since_keys += 1;
            if (!self.first_kex_done && seq == u32::MAX)
                || self.in_since_keys > u64::from(u32::MAX) + 1
            {
                return self.fail(DisconnectReason::PROTOCOL_ERROR, Error::SequenceWrap);
            }
            self.in_seq = seq.wrapping_add(1);
            let first = self.packets_received == 0;
            self.packets_received += 1;
            self.dispatch(&opened.payload, seq, first);
        }
    }

    fn on_version(&mut self, peer: String) {
        self.handshake.peer_version = Some(peer);
        self.version_done = true;
        let kexinit = self.local_kexinit();
        let raw = Message::KexInit(kexinit.clone()).encode();
        self.send_payload(&raw);
        self.handshake.local_kexinit = Some(KexInitRecord {
            raw,
            message: kexinit,
        });
    }

    fn local_kexinit(&mut self) -> KexInit {
        let mut k = KexInit::default();
        self.rng.fill_bytes(&mut k.cookie);
        let preference = self.preference.clone().unwrap_or_default();
        k.kex_algorithms = preference.kex;
        if self.role == Role::Client && self.session_id.is_none() {
            k.kex_algorithms.push(negotiate::EXT_INFO_CLIENT.to_owned());
        }
        if preference.strict_kex {
            k.kex_algorithms.push(
                match self.role {
                    Role::Server => negotiate::STRICT_SERVER,
                    Role::Client => negotiate::STRICT_CLIENT,
                }
                .to_owned(),
            );
        }
        k.server_host_key_algorithms = match self.role {
            Role::Server => self
                .host_keys
                .iter()
                .flat_map(|h| h.algorithms())
                .map(|a| (*a).to_owned())
                .collect(),
            Role::Client => preference.host_key.clone(),
        };
        let (cipher_s2c, mac_s2c) = preference
            .server_to_client
            .unwrap_or_else(|| (preference.cipher.clone(), preference.mac.clone()));
        k.encryption_algorithms_client_to_server = preference.cipher;
        k.encryption_algorithms_server_to_client = cipher_s2c;
        k.mac_algorithms_client_to_server = preference.mac;
        k.mac_algorithms_server_to_client = mac_s2c;
        k.compression_algorithms_client_to_server = names(negotiate::COMPRESSION);
        k.compression_algorithms_server_to_client = names(negotiate::COMPRESSION);
        k
    }

    fn strict(&self) -> bool {
        self.handshake
            .negotiated
            .as_ref()
            .is_some_and(|a| a.strict_kex)
    }

    fn dispatch(&mut self, payload: &[u8], seq: u32, first: bool) {
        if self.skip_next {
            self.skip_next = false;
            return;
        }
        #[cfg(feature = "test-support")]
        if self.raw_receive && self.first_kex_done {
            self.actions.push(Action::RawReceived(payload.to_vec()));
            return;
        }
        let n = payload[0];
        let strict_initial = self.strict() && !self.first_kex_done;
        match allowed::verdict(self.role, self.stage, n, strict_initial) {
            Verdict::Accept => {}
            Verdict::Ignore => return,
            Verdict::Unimplemented => {
                return self.send(&Message::Unimplemented(Unimplemented::new(seq)));
            }
            Verdict::Disconnect => {
                return self.fail(
                    DisconnectReason::PROTOCOL_ERROR,
                    Error::UnexpectedMessage { number: n },
                );
            }
        }
        if n == number::USERAUTH_REQUEST {
            return self.on_userauth_request(payload);
        }
        if n == number::USERAUTH_INFO_REQUEST {
            return self.on_info_request(payload);
        }
        let message = match Message::decode(payload) {
            Ok(m) => m,
            Err(e) => return self.fail(DisconnectReason::PROTOCOL_ERROR, Error::Decode(e)),
        };
        match message {
            Message::Disconnect(d) => {
                let phase = self.phase;
                self.close(Closed::Peer {
                    reason: DisconnectReason::from_code(d.reason),
                    description: d.description,
                    phase,
                })
            }
            Message::Ping(p) => self.send(&Message::Pong(Pong::new(p.data))),
            Message::Pong(_) => {}
            m @ (Message::GlobalRequest(_)
            | Message::RequestSuccess(_)
            | Message::RequestFailure(_)
            | Message::ChannelOpen(_)
            | Message::ChannelOpenConfirmation(_)
            | Message::ChannelOpenFailure(_)
            | Message::ChannelWindowAdjust(_)
            | Message::ChannelData(_)
            | Message::ChannelExtendedData(_)
            | Message::ChannelEof(_)
            | Message::ChannelClose(_)
            | Message::ChannelRequest(_)
            | Message::ChannelSuccess(_)
            | Message::ChannelFailure(_)) => {
                let steps = self.channels.handle(m);
                self.run(steps);
            }
            Message::Ignore(_) | Message::Debug(_) | Message::Unimplemented(_) => {}
            Message::KexInit(k) => self.on_kexinit(payload.to_vec(), k, first),
            Message::KexEcdhInit(m) => self.on_ecdh_init(&m.q_c),
            Message::KexEcdhReply(m) => self.on_ecdh_reply(&m),
            Message::NewKeys(_) => self.on_newkeys(),
            Message::ServiceRequest(r) => self.on_service_request(&r.service),
            Message::ServiceAccept(a) => self.on_service_accept(&a.service),
            Message::ExtInfo(e) => self.on_ext_info(e.extensions),
            Message::UserauthFailure(f) => self.on_userauth_failure(f.methods, f.partial_success),
            Message::UserauthSuccess(_) => self.on_userauth_success(),
            Message::UserauthBanner(b) => {
                self.actions.push(Action::AuthBanner { message: b.message })
            }
            _ => self.fail(
                DisconnectReason::PROTOCOL_ERROR,
                Error::UnexpectedMessage { number: n },
            ),
        }
    }

    fn on_kexinit(&mut self, raw: Vec<u8>, peer: KexInit, first: bool) {
        self.handshake.peer_kexinit = Some(KexInitRecord {
            raw,
            message: peer.clone(),
        });
        let local = &self
            .handshake
            .local_kexinit
            .as_ref()
            .expect("KEXINIT sent")
            .message;
        let (client, server) = match self.role {
            Role::Server => (&peer, local),
            Role::Client => (local, &peer),
        };
        let negotiated = negotiate::negotiate(client, server);
        let guessed_right = negotiate::guessed_right(client, server);
        let algs = match negotiated {
            Ok(a) => a,
            Err(category) => {
                let handshake = Box::new(self.handshake.clone());
                return self.fail(
                    DisconnectReason::KEY_EXCHANGE_FAILED,
                    Error::NoCommonAlgorithm {
                        category,
                        handshake,
                    },
                );
            }
        };
        let strict = algs.strict_kex;
        self.handshake.negotiated = Some(algs);
        if strict && !first {
            return self.fail(DisconnectReason::PROTOCOL_ERROR, Error::StrictKexViolation);
        }
        self.skip_next = peer.first_kex_packet_follows && !guessed_right;
        self.stage = Stage::KexEcdh;
        let mut exchange = Exchange {
            client: None,
            incoming: None,
        };
        if self.role == Role::Client {
            let method = self.kex_method();
            let start = kex::client_start(method, &mut *self.rng);
            let hashed = kex::hashed_public(method, &start.public);
            exchange.client = Some((start.secret, hashed));
            self.exchange = Some(exchange);
            self.send(&Message::KexEcdhInit(KexEcdhInit::new(start.public)));
        } else {
            self.exchange = Some(exchange);
        }
    }

    /// The negotiated key exchange method.
    fn kex_method(&self) -> kex::Method {
        self.handshake
            .negotiated
            .as_ref()
            .and_then(|a| kex::Method::from_name(&a.kex))
            .expect("a key exchange this crate implements was negotiated")
    }

    fn on_ecdh_init(&mut self, q_c: &[u8]) {
        let method = self.kex_method();
        let Some((q_s, k)) = kex::server_respond(method, q_c, &mut *self.rng) else {
            return self.fail(DisconnectReason::KEY_EXCHANGE_FAILED, Error::KeyExchange);
        };
        let algorithm = self
            .handshake
            .negotiated
            .as_ref()
            .map(|a| a.host_key.clone())
            .expect("negotiated");
        let key = self
            .host_keys
            .iter()
            .position(|h| h.algorithms().contains(&algorithm.as_str()))
            .expect("the negotiated host key algorithm is one the server offered");
        let k_s = self.host_keys[key].public_blob();
        let h = self.exchange_hash(
            &k_s,
            &kex::hashed_public(method, q_c),
            &kex::hashed_public(method, &q_s),
            &k,
        );
        let signature = self.host_keys[key].sign(&algorithm, &h, &mut *self.rng);
        self.send(&Message::KexEcdhReply(KexEcdhReply::new(
            k_s, q_s, signature,
        )));
        self.finish_exchange(&k, &h);
    }

    fn on_ecdh_reply(&mut self, reply: &KexEcdhReply) {
        let Some((secret, q_c)) = self.exchange.as_mut().and_then(|e| e.client.take()) else {
            return self.fail(
                DisconnectReason::PROTOCOL_ERROR,
                Error::UnexpectedMessage {
                    number: number::KEX_ECDH_REPLY,
                },
            );
        };
        let method = self.kex_method();
        let Some(k) = kex::client_finish(secret, &reply.q_s) else {
            return self.fail(DisconnectReason::KEY_EXCHANGE_FAILED, Error::KeyExchange);
        };
        let h = self.exchange_hash(
            &reply.host_key,
            &q_c,
            &kex::hashed_public(method, &reply.q_s),
            &k,
        );
        if !self.verify_host_signature(&reply.host_key, &reply.signature, &h) {
            return self.fail(
                DisconnectReason::KEY_EXCHANGE_FAILED,
                Error::HostKeySignature,
            );
        }
        self.peer_host_key = Some(reply.host_key.clone());
        self.host_key_pending = Some(PendingKex { k, h });
        self.actions.push(Action::VerifyHostKey {
            key: reply.host_key.clone(),
        });
    }

    fn verify_host_signature(&self, blob: &[u8], signature: &[u8], h: &[u8]) -> bool {
        let algorithm = self
            .handshake
            .negotiated
            .as_ref()
            .map(|a| a.host_key.as_str())
            .expect("negotiated");
        crate::key::verify(blob, algorithm, signature, h)
    }

    fn exchange_hash(&self, k_s: &[u8], q_c: &[u8], q_s: &[u8], k: &[u8]) -> Vec<u8> {
        let local_v = self.handshake.local_version.as_bytes();
        let peer_v = self
            .handshake
            .peer_version
            .as_deref()
            .unwrap_or_default()
            .as_bytes();
        let local_i = &self
            .handshake
            .local_kexinit
            .as_ref()
            .expect("KEXINIT sent")
            .raw;
        let peer_i = &self
            .handshake
            .peer_kexinit
            .as_ref()
            .expect("KEXINIT received")
            .raw;
        let (v_c, v_s, i_c, i_s) = match self.role {
            Role::Server => (peer_v, local_v, peer_i, local_i),
            Role::Client => (local_v, peer_v, local_i, peer_i),
        };
        kex::exchange_hash(
            self.kex_method().hash(),
            &kex::HashInput {
                v_c,
                v_s,
                i_c,
                i_s,
                k_s,
                q_c,
                q_s,
                k,
            },
        )
    }

    /// The packet protection for one direction, from key material derived with letters
    /// `iv`, `iv + 2` and `iv + 4` (RFC 4253 §7.2).
    fn direction_cipher(&self, k: &[u8], h: &[u8], session_id: &[u8], to_server: bool) -> Cipher {
        let algs = self.handshake.negotiated.as_ref().expect("negotiated");
        let (cipher, mac, iv) = if to_server {
            (
                &algs.cipher_client_to_server,
                &algs.mac_client_to_server,
                b'A',
            )
        } else {
            (
                &algs.cipher_server_to_client,
                &algs.mac_server_to_client,
                b'B',
            )
        };
        let hash = self.kex_method().hash();
        let sizes = packet::key_sizes(cipher, mac.as_deref());
        let iv_bytes = kex::derive(hash, k, h, iv, session_id, sizes.iv);
        let key = kex::derive(hash, k, h, iv + 2, session_id, sizes.key);
        let mac_key = kex::derive(hash, k, h, iv + 4, session_id, sizes.mac);
        Cipher::new(cipher, mac.as_deref(), &key, &iv_bytes, &mac_key)
    }

    /// Sends `SSH_MSG_NEWKEYS` and takes the new outgoing keys into use.
    fn finish_exchange(&mut self, k: &[u8], h: &[u8]) {
        let first = self.session_id.is_none();
        let session_id = self.session_id.get_or_insert_with(|| h.to_vec()).clone();
        let client_to_server = self.direction_cipher(k, h, &session_id, true);
        let server_to_client = self.direction_cipher(k, h, &session_id, false);
        let (outgoing, incoming) = match self.role {
            Role::Server => (server_to_client, client_to_server),
            Role::Client => (client_to_server, server_to_client),
        };
        self.send(&Message::NewKeys(NewKeys::default()));
        self.sealing = outgoing;
        self.out_since_keys = 0;
        if self.strict() {
            self.out_seq = 0;
        }
        if let Some(e) = self.exchange.as_mut() {
            e.incoming = Some(incoming);
        }
        self.stage = Stage::NewKeys;
        if first
            && self.role == Role::Server
            && self.send_ext_info
            && self.peer_offered("ext-info-c")
        {
            self.send(&Message::ExtInfo(ExtInfo::new(vec![
                (
                    "server-sig-algs".to_owned(),
                    SERVER_SIG_ALGS.as_bytes().to_vec(),
                ),
                ("ping@openssh.com".to_owned(), b"0".to_vec()),
            ])));
        }
    }

    /// Whether the peer's `SSH_MSG_KEXINIT` listed `name` among its key exchange algorithms.
    fn peer_offered(&self, name: &str) -> bool {
        self.handshake
            .peer_kexinit
            .as_ref()
            .is_some_and(|k| k.message.kex_algorithms.iter().any(|a| a == name))
    }

    fn on_userauth_request(&mut self, payload: &[u8]) {
        let request = match userauth::request(payload) {
            Ok(r) => r,
            Err(e) => return self.fail(DisconnectReason::PROTOCOL_ERROR, Error::Decode(e)),
        };
        let Some(auth) = self.auth.as_mut() else {
            return self.fail(
                DisconnectReason::PROTOCOL_ERROR,
                Error::UnexpectedMessage {
                    number: number::USERAUTH_REQUEST,
                },
            );
        };
        auth.attempt(request.method);
        if request.service != userauth::CONNECTION {
            return self.fail(
                DisconnectReason::SERVICE_NOT_AVAILABLE,
                Error::ServiceNotAvailable,
            );
        }
        if request.method != "password" {
            return self.auth_failed(request.method);
        }
        match userauth::password(request.method_data) {
            Ok(password) => {
                auth.pending = true;
                self.actions.push(Action::PasswordRequest(PasswordRequest {
                    user: request.user.to_vec(),
                    password,
                }));
            }
            Err(e) => self.fail(DisconnectReason::PROTOCOL_ERROR, Error::Decode(e)),
        }
    }

    fn auth_failed(&mut self, method: &str) {
        let Some(auth) = self.auth.as_mut() else {
            return;
        };
        let after = auth.failed(method);
        if let AfterFailure::TooManyFailures = after {
            return self.fail(DisconnectReason::PROTOCOL_ERROR, Error::TooManyAuthFailures);
        }
        let methods = userauth::METHODS.iter().map(|m| (*m).to_owned()).collect();
        self.send(&Message::UserauthFailure(UserauthFailure::new(
            methods, false,
        )));
        if let AfterFailure::FailureThenTooManyAttempts = after {
            self.fail(DisconnectReason::PROTOCOL_ERROR, Error::TooManyAuthAttempts);
        }
    }

    /// Ends the connection over message `n`, which the client's authentication state does not
    /// take.
    fn unexpected(&mut self, n: u8) {
        self.fail(
            DisconnectReason::PROTOCOL_ERROR,
            Error::UnexpectedMessage { number: n },
        );
    }

    fn on_ext_info(&mut self, extensions: Vec<(String, Vec<u8>)>) {
        if self.stage == Stage::Service {
            if self.ext_info.is_some() {
                return self.unexpected(number::EXT_INFO);
            }
            self.ext_info = Some(extensions);
            return;
        }
        match self.client_auth.as_mut() {
            Some(a) if a.attempt.is_some() && !a.ext_info => a.ext_info = true,
            _ => self.unexpected(number::EXT_INFO),
        }
    }

    fn on_userauth_failure(&mut self, methods: Vec<String>, partial_success: bool) {
        let Some(auth) = self.client_auth.as_mut().filter(|a| a.attempt.is_some()) else {
            return self.unexpected(number::USERAUTH_FAILURE);
        };
        auth.attempt = None;
        auth.questions = None;
        let queried = auth.key.take().is_some_and(|k| !k.signed);
        auth.methods = methods.clone();
        self.actions.push(if queried {
            Action::PublicKeyRefused { methods }
        } else {
            Action::AuthFailure {
                methods,
                partial_success,
            }
        });
    }

    fn on_userauth_success(&mut self) {
        let Some(auth) = self.client_auth.as_mut().filter(|a| a.attempt.is_some()) else {
            return self.unexpected(number::USERAUTH_SUCCESS);
        };
        auth.attempt = None;
        auth.questions = None;
        auth.key = None;
        self.stage = Stage::Connected;
        self.phase = Phase::Connected;
    }

    /// `SSH_MSG_USERAUTH_INFO_REQUEST` under keyboard-interactive,
    /// `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` under password and `SSH_MSG_USERAUTH_PK_OK` under
    /// publickey, which share a number.
    fn on_info_request(&mut self, payload: &[u8]) {
        let Some(auth) = self.client_auth.as_mut() else {
            return self.unexpected(number::USERAUTH_INFO_REQUEST);
        };
        match (auth.attempt, auth.questions) {
            (Some(Method::PublicKey), _) => self.on_pk_ok(payload),
            (Some(Method::Password), _) => {
                auth.attempt = None;
                let methods = auth.methods.clone();
                self.actions.push(Action::AuthFailure {
                    methods,
                    partial_success: false,
                });
            }
            (Some(Method::KeyboardInteractive), None) => match userauth::info_request(payload) {
                Ok(request) => {
                    auth.questions = Some(request.prompts.len());
                    self.actions.push(Action::KeyboardInteractive(request));
                }
                Err(e) => self.fail(DisconnectReason::PROTOCOL_ERROR, Error::Decode(e)),
            },
            _ => self.unexpected(number::USERAUTH_INFO_REQUEST),
        }
    }

    /// Signs and sends the request the server accepted the key of, or takes a `PK_OK` for
    /// another key or algorithm as a refusal.
    fn on_pk_ok(&mut self, payload: &[u8]) {
        let (algorithm, blob) = match userauth::pk_ok(payload) {
            Ok(ok) => ok,
            Err(e) => return self.fail(DisconnectReason::PROTOCOL_ERROR, Error::Decode(e)),
        };
        let session_id = self
            .session_id
            .clone()
            .expect("authentication follows the first key exchange");
        let Some(auth) = self.client_auth.as_mut() else {
            return;
        };
        let Some(attempt) = auth.key.as_mut().filter(|k| !k.signed) else {
            return self.unexpected(number::USERAUTH_INFO_REQUEST);
        };
        let public = attempt.key.public_blob();
        if !attempt.key.algorithms().contains(&algorithm) || blob != public {
            auth.attempt = None;
            auth.key = None;
            let methods = auth.methods.clone();
            self.actions.push(Action::PublicKeyRefused { methods });
            return;
        }
        attempt.signed = true;
        let data =
            userauth::publickey_signed_data(&session_id, &auth.user, attempt.algorithm, &public);
        let signature = attempt.key.sign(attempt.algorithm, &data, &mut *self.rng);
        let request =
            userauth::publickey_request(&auth.user, attempt.algorithm, &public, Some(&signature));
        self.send_payload(&request);
    }

    fn on_newkeys(&mut self) {
        let incoming = self.exchange.take().and_then(|e| e.incoming);
        let Some(incoming) = incoming else {
            return self.fail(
                DisconnectReason::PROTOCOL_ERROR,
                Error::UnexpectedMessage {
                    number: number::NEWKEYS,
                },
            );
        };
        self.opening = incoming;
        self.in_since_keys = 0;
        if self.strict() {
            self.in_seq = 0;
        }
        self.first_kex_done = true;
        self.stage = Stage::Service;
        if self.role == Role::Client {
            self.send(&Message::ServiceRequest(ServiceRequest::new(USERAUTH)));
        }
    }

    fn on_service_request(&mut self, service: &str) {
        if service != USERAUTH {
            return self.fail(
                DisconnectReason::SERVICE_NOT_AVAILABLE,
                Error::ServiceNotAvailable,
            );
        }
        self.send(&Message::ServiceAccept(ServiceAccept::new(USERAUTH)));
        self.stage = Stage::Auth;
        self.phase = Phase::Auth;
    }

    fn on_service_accept(&mut self, service: &str) {
        if service != USERAUTH {
            return self.fail(
                DisconnectReason::PROTOCOL_ERROR,
                Error::UnexpectedMessage {
                    number: number::SERVICE_ACCEPT,
                },
            );
        }
        self.stage = Stage::Auth;
        self.phase = Phase::Auth;
    }
}
