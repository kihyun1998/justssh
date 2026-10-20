# Crypto: RustCrypto stable releases only, no primitives of our own

Every crypto primitive comes from a vetted implementation; none is written here. puressh's home-grown primitives are the weakness we are avoiding.

We depend only on the latest **stable** release of each RustCrypto crate and never on a release candidate. The reason is IronRDP's dependency sspi. It pins exact release candidates such as `rsa =0.10.0-rc.18`, and Cargo admits only one version per semver-compatible range in a build. If justssh required a different release candidate, the build would fail as soon as justssh and sspi share a binary.

Most of the new generation is already stable as of 2026-10: digest 0.11, sha2 0.11, ed25519- and x25519-dalek 3, ml-kem 0.3 and rand_core 0.10. Those builds line up with sspi, so we take them.

rsa is the exception, because its new line is still a release candidate. We use rsa 0.9, and the older digest, sha1 and rand_core it brings are confined to the RSA signing code.

A CI check builds justssh together with IronRDP and sspi to keep that true. We will move to rsa 0.10 when it is released as stable.
