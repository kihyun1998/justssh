//! Which message numbers each stage of the connection takes (ADR-0002). Every received packet
//! passes through [`verdict`] before it is decoded.

use justssh_wire::number;

use super::Role;

/// Where the transport is, as far as incoming messages are concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Waiting for the peer's `SSH_MSG_KEXINIT`.
    KexInit,
    /// Waiting for `SSH_MSG_KEX_ECDH_INIT` (server) or `SSH_MSG_KEX_ECDH_REPLY` (client).
    KexEcdh,
    /// This side has sent `SSH_MSG_NEWKEYS` and waits for the peer's.
    NewKeys,
    /// Waiting for `SSH_MSG_SERVICE_REQUEST` (server) or `SSH_MSG_SERVICE_ACCEPT` (client).
    Service,
    /// User authentication.
    Auth,
    /// Authenticated.
    Connected,
}

/// What to do with a received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accept,
    Disconnect,
    /// Drop it without a reply (RFC 4252 §5: requests after `SSH_MSG_USERAUTH_SUCCESS`).
    Ignore,
    /// Answer `SSH_MSG_UNIMPLEMENTED` and carry on (RFC 4253 §11.4).
    Unimplemented,
}

/// The verdict for message `n` arriving at `role` in `stage`. `strict_initial` is true while
/// strict key exchange is in force and the first key exchange has not finished.
pub(crate) fn verdict(role: Role, stage: Stage, n: u8, strict_initial: bool) -> Verdict {
    use Verdict::{Accept, Disconnect, Ignore, Unimplemented};

    let accept_if = |ok: bool| if ok { Accept } else { Disconnect };
    match n {
        number::DISCONNECT => Accept,
        number::IGNORE | number::DEBUG | number::UNIMPLEMENTED => accept_if(!strict_initial),
        number::KEXINIT => accept_if(matches!(
            stage,
            Stage::KexInit | Stage::Service | Stage::Auth | Stage::Connected
        )),
        number::KEX_ECDH_INIT => accept_if(role == Role::Server && stage == Stage::KexEcdh),
        number::KEX_ECDH_REPLY => accept_if(role == Role::Client && stage == Stage::KexEcdh),
        number::NEWKEYS => accept_if(stage == Stage::NewKeys),
        number::SERVICE_REQUEST => accept_if(role == Role::Server && stage == Stage::Service),
        number::SERVICE_ACCEPT => accept_if(role == Role::Client && stage == Stage::Service),
        number::USERAUTH_REQUEST if role == Role::Server && stage == Stage::Connected => Ignore,
        number::USERAUTH_REQUEST => accept_if(role == Role::Server && stage == Stage::Auth),
        number::USERAUTH_FAILURE
        | number::USERAUTH_SUCCESS
        | number::USERAUTH_BANNER
        | number::USERAUTH_INFO_REQUEST => accept_if(role == Role::Client && stage == Stage::Auth),
        number::EXT_INFO => {
            accept_if(role == Role::Client && matches!(stage, Stage::Service | Stage::Auth))
        }
        number::PING | number::PONG => accept_if(stage == Stage::Connected),
        number::GLOBAL_REQUEST..=number::REQUEST_FAILURE => accept_if(stage == Stage::Connected),
        number::CHANNEL_OPEN..=number::CHANNEL_FAILURE => accept_if(stage == Stage::Connected),
        n if !number::is_known(n) && stage == Stage::Connected => Unimplemented,
        _ => Disconnect,
    }
}

#[cfg(test)]
mod tests {
    use super::{Role, Stage, Verdict, verdict};

    /// The numbers each side takes in each stage, written from RFC 4253, 4252 and 4254 and
    /// ADR-0002 as one list per stage rather than one rule per number.
    fn allowed(role: Role, stage: Stage) -> Vec<u8> {
        let mut n = vec![1, 2, 3, 4];
        let channel_protocol: Vec<u8> = [80, 81, 82]
            .into_iter()
            .chain(90..=100)
            .chain([192, 193])
            .collect();
        n.extend(match (role, stage) {
            (_, Stage::KexInit) => vec![20],
            (Role::Server, Stage::KexEcdh) => vec![30],
            (Role::Client, Stage::KexEcdh) => vec![31],
            (_, Stage::NewKeys) => vec![21],
            (Role::Server, Stage::Service) => vec![5, 20],
            (Role::Client, Stage::Service) => vec![6, 7, 20],
            (Role::Server, Stage::Auth) => vec![20, 50],
            (Role::Client, Stage::Auth) => vec![7, 20, 51, 52, 53, 60],
            (_, Stage::Connected) => [vec![20], channel_protocol].concat(),
        });
        n
    }

    /// The numbers counted as known: every number the wire crate decodes, and 60, which a
    /// client reads during keyboard-interactive authentication, at either side.
    fn known(n: u8) -> bool {
        matches!(n, 1..=7 | 20 | 21 | 30 | 31 | 50..=53 | 60 | 80..=82 | 90..=100 | 192 | 193)
    }

    fn expected(role: Role, stage: Stage, n: u8, strict_initial: bool) -> Verdict {
        if strict_initial && matches!(n, 2..=4) {
            return Verdict::Disconnect;
        }
        if role == Role::Server && stage == Stage::Connected && n == 50 {
            return Verdict::Ignore;
        }
        if allowed(role, stage).contains(&n) {
            return Verdict::Accept;
        }
        if stage == Stage::Connected && !known(n) {
            return Verdict::Unimplemented;
        }
        Verdict::Disconnect
    }

    #[test]
    fn every_cell_of_the_table_is_what_the_rfcs_and_adr_0002_say() {
        let mut differ = Vec::new();
        for role in [Role::Server, Role::Client] {
            for stage in [
                Stage::KexInit,
                Stage::KexEcdh,
                Stage::NewKeys,
                Stage::Service,
                Stage::Auth,
                Stage::Connected,
            ] {
                for n in 0..=u8::MAX {
                    for strict in [false, true] {
                        let (got, want) = (
                            verdict(role, stage, n, strict),
                            expected(role, stage, n, strict),
                        );
                        if got != want {
                            differ.push(format!(
                                "{role:?} {stage:?} {n} strict={strict}: {got:?}, want {want:?}"
                            ));
                        }
                    }
                }
            }
        }
        assert!(differ.is_empty(), "{}", differ.join("\n"));
    }
}
