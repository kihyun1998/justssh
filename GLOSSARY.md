# justssh

A Rust SSH client and server library whose connection layer carries requests without interpreting them, so a gatekeeper can pass a session through to an upstream server unchanged.

## Language

**Opaque Request**:
A global or channel request held as its name, want_reply flag and payload bytes, with nothing parsed out of the payload.
_Avoid_: raw request, envelope

**Opaque Channel Open**:
A channel open held as its channel type and type-specific payload bytes.
_Avoid_: raw channel open

**Pass-through**:
Handing an Opaque Request, Opaque Channel Open or channel data to the other side without interpreting it.
_Avoid_: relay, forward, envelope relay (봉투째 중계)
