# Three crates, and growth goes on top

The workspace starts as three crates, split where the dependencies differ:
- `justssh-wire` encodes and decodes messages and has no dependencies.
- `justssh` is the sans-IO core: the transport, authentication and connection state machines, the typed codecs and the crypto.
- `justssh-tokio` is the only crate that depends on a runtime.

Transport, authentication and connection are modules, not crates. They share one state machine, and making each a crate would turn that shared internal state into public API we would then have to keep stable.

Later capabilities are added as crates layered on the Opaque API (for example `justssh-sftp`), so generalising never reopens the core. This follows justrdp's pdu / core / tokio split.

## Addendum (2026-10-22): key files are a fourth crate

`justssh-keys` reads and writes private key files and yields the core's `PrivateKey`. It sits on top of the core, where this record puts later capabilities, so the key derivation and cipher modes that only files need (bcrypt-pbkdf, AES-CBC) stay out of the core and away from a consumer that never reads a key file. The maintainer chose this on #21 over a module in the core.

## Addendum (2026-10-23): the minimal broker is an unpublished crate

`justssh-broker` is the minimal broker that acwbroker's blackbox harness drives in place of acwbroker (#1). It is a binary built on the other crates, and it is never published (`publish = false`). It is not a capability other consumers build on, so it is outside the layering above. The maintainer chose an unpublished crate on #15 over an example in `justssh-tokio`. An example would have needed `justssh-keys` as a dev-dependency of the adapter, and it would have grown into one long file as #16 adds policy and the upstream side.
