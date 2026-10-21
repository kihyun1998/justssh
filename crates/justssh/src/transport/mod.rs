//! The transport layer (RFC 4253) for either role: version exchange, key exchange, the binary
//! packet protocol and the `ssh-userauth` service request.

mod allowed;
mod kex;
mod negotiate;
mod packet;
mod userauth;
mod version;

use ed25519_dalek::{Signature, VerifyingKey};
use justssh_wire::{
    Disconnect, ExtInfo, KexEcdhInit, KexEcdhReply, KexInit, Message, NewKeys, Pong, Reader,
    ServiceAccept, ServiceRequest, Unimplemented, UserauthFailure, UserauthSuccess, number,
};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::config::{BoxRng, HostKey};
use crate::connection::{ChannelId, ChannelInfo, Channels, Step};
use crate::event::{Action, Closed, DisconnectReason, Error, Event, PasswordRequest, Phase};
use crate::handshake::{Handshake, KexInitRecord};

use allowed::{Stage, Verdict};
use packet::{ChaChaKeys, Cipher, OpenError};
use userauth::{AfterFailure, ServerAuth};
use version::{Line, VersionError};

const USERAUTH: &str = "ssh-userauth";

/// Most input held unprocessed while a verdict is pending: one largest packet with its length
/// field and MAC.
const PENDING_INPUT: usize = packet::MAX_PACKET + 4 + 16;

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

/// Key exchange state that lives only until `SSH_MSG_NEWKEYS`.
struct Exchange {
    /// The client's ephemeral key and the public half already sent.
    client: Option<(EphemeralSecret, [u8; 32])>,
    /// Keys for the incoming direction, taken into use on the peer's `SSH_MSG_NEWKEYS`.
    incoming: Option<Cipher>,
}

pub(crate) struct Transport {
    role: Role,
    host_key: Option<HostKey>,
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
    channels: Channels,
    #[cfg(feature = "test-support")]
    raw_receive: bool,
    actions: Vec<Action>,
}

impl Transport {
    pub(crate) fn new(
        role: Role,
        host_key: Option<HostKey>,
        rng: BoxRng,
        local_version: String,
        max_auth_tries: u32,
        channel_window: u32,
        channel_max_packet: u32,
    ) -> Self {
        Transport {
            role,
            host_key,
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
                if self.auth_pending() && self.inbuf.len() > PENDING_INPUT {
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

    pub(crate) fn channel_info(&self, id: ChannelId) -> Option<ChannelInfo> {
        self.channels.info(id)
    }

    fn auth_pending(&self) -> bool {
        self.auth.as_ref().is_some_and(|a| a.pending)
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
        while self.phase != Phase::Closed && !self.auth_pending() {
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
        let names = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        k.kex_algorithms = names(negotiate::KEX);
        k.kex_algorithms.push(
            match self.role {
                Role::Server => negotiate::STRICT_SERVER,
                Role::Client => negotiate::STRICT_CLIENT,
            }
            .to_owned(),
        );
        k.server_host_key_algorithms = match &self.host_key {
            Some(h) => vec![h.algorithm().to_owned()],
            None => names(negotiate::HOST_KEY),
        };
        k.encryption_algorithms_client_to_server = names(negotiate::CIPHER);
        k.encryption_algorithms_server_to_client = names(negotiate::CIPHER);
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
            let secret = EphemeralSecret::random_from_rng(&mut *self.rng);
            let public = *PublicKey::from(&secret).as_bytes();
            exchange.client = Some((secret, public));
            self.exchange = Some(exchange);
            self.send(&Message::KexEcdhInit(KexEcdhInit::new(public.to_vec())));
        } else {
            self.exchange = Some(exchange);
        }
    }

    fn peer_public(bytes: &[u8]) -> Option<PublicKey> {
        <[u8; 32]>::try_from(bytes).ok().map(PublicKey::from)
    }

    fn on_ecdh_init(&mut self, q_c: &[u8]) {
        let Some(client_public) = Self::peer_public(q_c) else {
            return self.fail(DisconnectReason::KEY_EXCHANGE_FAILED, Error::KeyExchange);
        };
        let secret = EphemeralSecret::random_from_rng(&mut *self.rng);
        let q_s = *PublicKey::from(&secret).as_bytes();
        let shared = Zeroizing::new(*secret.diffie_hellman(&client_public).as_bytes());
        if shared.iter().all(|&b| b == 0) {
            return self.fail(DisconnectReason::KEY_EXCHANGE_FAILED, Error::KeyExchange);
        }
        let host_key = self.host_key.clone().expect("server has a host key");
        let k_s = host_key.public_blob();
        let h = self.exchange_hash(&k_s, q_c, &q_s, &*shared);
        let signature = host_key.sign(&h);
        self.send(&Message::KexEcdhReply(KexEcdhReply::new(
            k_s,
            q_s.to_vec(),
            signature,
        )));
        self.finish_exchange(&*shared, &h);
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
        let Some(server_public) = Self::peer_public(&reply.q_s) else {
            return self.fail(DisconnectReason::KEY_EXCHANGE_FAILED, Error::KeyExchange);
        };
        let shared = Zeroizing::new(*secret.diffie_hellman(&server_public).as_bytes());
        if shared.iter().all(|&b| b == 0) {
            return self.fail(DisconnectReason::KEY_EXCHANGE_FAILED, Error::KeyExchange);
        }
        let h = self.exchange_hash(&reply.host_key, &q_c, &reply.q_s, &*shared);
        if !self.verify_host_signature(&reply.host_key, &reply.signature, &h) {
            return self.fail(
                DisconnectReason::KEY_EXCHANGE_FAILED,
                Error::HostKeySignature,
            );
        }
        self.peer_host_key = Some(reply.host_key.clone());
        self.finish_exchange(&*shared, &h);
    }

    fn verify_host_signature(&self, blob: &[u8], signature: &[u8], h: &[u8]) -> bool {
        let algorithm = self
            .handshake
            .negotiated
            .as_ref()
            .map(|a| a.host_key.as_str());
        let mut key = Reader::new(blob);
        let mut sig = Reader::new(signature);
        let parsed = (|| {
            let key_alg = key.utf8().ok()?;
            let key_bytes: [u8; 32] = key.string().ok()?.try_into().ok()?;
            key.finish().ok()?;
            let sig_alg = sig.utf8().ok()?;
            let sig_bytes: [u8; 64] = sig.string().ok()?.try_into().ok()?;
            sig.finish().ok()?;
            Some((key_alg, key_bytes, sig_alg, sig_bytes))
        })();
        let Some((key_alg, key_bytes, sig_alg, sig_bytes)) = parsed else {
            return false;
        };
        if Some(key_alg) != algorithm || sig_alg != key_alg {
            return false;
        }
        let Ok(public) = VerifyingKey::from_bytes(&key_bytes) else {
            return false;
        };
        public
            .verify_strict(h, &Signature::from_bytes(&sig_bytes))
            .is_ok()
    }

    fn exchange_hash(&self, k_s: &[u8], q_c: &[u8], q_s: &[u8], shared: &[u8]) -> Vec<u8> {
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
        kex::exchange_hash(&kex::HashInput {
            v_c,
            v_s,
            i_c,
            i_s,
            k_s,
            q_c,
            q_s,
            shared,
        })
    }

    /// Sends `SSH_MSG_NEWKEYS` and takes the new outgoing keys into use.
    fn finish_exchange(&mut self, shared: &[u8], h: &[u8]) {
        let first = self.session_id.is_none();
        let session_id = self.session_id.get_or_insert_with(|| h.to_vec()).clone();
        let client_to_server = kex::derive(shared, h, b'C', &session_id, 64);
        let server_to_client = kex::derive(shared, h, b'D', &session_id, 64);
        let (outgoing, incoming) = match self.role {
            Role::Server => (server_to_client, client_to_server),
            Role::Client => (client_to_server, server_to_client),
        };
        self.send(&Message::NewKeys(NewKeys::default()));
        self.sealing = Cipher::ChaCha(ChaChaKeys::from_material(&outgoing));
        self.out_since_keys = 0;
        if self.strict() {
            self.out_seq = 0;
        }
        if let Some(e) = self.exchange.as_mut() {
            e.incoming = Some(Cipher::ChaCha(ChaChaKeys::from_material(&incoming)));
        }
        self.stage = Stage::NewKeys;
        if first && self.role == Role::Server && self.peer_offered("ext-info-c") {
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
