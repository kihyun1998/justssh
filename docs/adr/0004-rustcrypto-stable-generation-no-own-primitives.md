# Crypto: RustCrypto stable releases only, no primitives of our own

Every crypto primitive comes from a vetted implementation; none is written here. puressh's home-grown primitives are the weakness we are avoiding.

We depend only on the latest **stable** release of each RustCrypto crate and never on a release candidate. The reason is IronRDP's dependency sspi. It pins exact release candidates such as `rsa =0.10.0-rc.18`, and Cargo admits only one version per semver-compatible range in a build. If justssh required a different release candidate, the build would fail as soon as justssh and sspi share a binary.

Most of the new generation is already stable as of 2026-10: digest 0.11, sha2 0.11, ed25519- and x25519-dalek 3, ml-kem 0.3 and rand_core 0.10. Those builds line up with sspi, so we take them.

rsa is the exception, because its new line is still a release candidate. We use rsa 0.9, and the older digest, sha1 and rand_core it brings are confined to the RSA signing code.

A CI check builds justssh together with IronRDP and sspi to keep that true. We will move to rsa 0.10 when it is released as stable.

## Amendment (2026-10-21): stable-only is not enough; the coexistence build is the guarantee

The first coexistence build (#2) showed that pinning to stable releases does not prevent conflicts. The published `ironrdp` 0.17 contains `picky =7.0.0-rc.25`, which pins `curve25519-dalek =5.0.0-rc.1`. ed25519-dalek 3 requires the stable 5.0.0. Both versions fall in Cargo's 5.x range, so the two cannot be built together.

The general case: a dependency that pins a release candidate conflicts with anyone who has moved to the stable release in the same range. Avoiding release candidates ourselves cannot prevent that.

What guarantees coexistence is the coexistence build. It targets the IronRDP the broker will ship with, which is Devolutions/IronRDP master pinned to a revision (`66bfd60`, 2026-10-20, picky rc.26), not the latest crates.io release. That revision builds with justssh, and the pin is raised by hand.
