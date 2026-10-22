# Three crates, and growth goes on top

The workspace starts as three crates, split where the dependencies differ:
- `justssh-wire` encodes and decodes messages and has no dependencies.
- `justssh` is the sans-IO core: the transport, authentication and connection state machines, the typed codecs and the crypto.
- `justssh-tokio` is the only crate that depends on a runtime.

Transport, authentication and connection are modules, not crates. They share one state machine, and making each a crate would turn that shared internal state into public API we would then have to keep stable.

Later capabilities are added as crates layered on the Opaque API (for example `justssh-sftp`), so generalising never reopens the core. This follows justrdp's pdu / core / tokio split.

## Addendum (2026-10-22): key files are a fourth crate

`justssh-keys` reads and writes private key files and yields the core's `PrivateKey`. It sits on top of the core, where this record puts later capabilities, so the key derivation and cipher modes that only files need (bcrypt-pbkdf, AES-CBC) stay out of the core and away from a consumer that never reads a key file. The maintainer chose this on #21 over a module in the core.
