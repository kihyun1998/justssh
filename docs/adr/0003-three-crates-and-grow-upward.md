# Three crates, and growth goes on top

The workspace starts as three crates, split where the dependencies differ:
- `justssh-wire` encodes and decodes messages and has no dependencies.
- `justssh` is the sans-IO core: the transport, authentication and connection state machines, the typed codecs and the crypto.
- `justssh-tokio` is the only crate that depends on a runtime.

Transport, authentication and connection are modules, not crates. They share one state machine, and making each a crate would turn that shared internal state into public API we would then have to keep stable.

Later capabilities are added as crates layered on the Opaque API (for example `justssh-sftp`), so generalising never reopens the core. This follows justrdp's pdu / core / tokio split.
