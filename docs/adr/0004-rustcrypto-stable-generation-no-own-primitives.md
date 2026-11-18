# Crypto: RustCrypto stable releases only, no primitives of our own

Every crypto primitive comes from a vetted implementation; none is written here. puressh's home-grown primitives are the weakness we are avoiding.

We depend only on the latest **stable** release of each RustCrypto crate and never on a release candidate. The reason is IronRDP's dependency sspi. It pins exact release candidates such as `rsa =0.10.0-rc.18`, and Cargo admits only one version per semver-compatible range in a build. If justssh required a different release candidate, the build would fail as soon as justssh and sspi share a binary.

Most of the new generation is already stable as of 2026-10: digest 0.11, sha2 0.11, ed25519- and x25519-dalek 3, ml-kem 0.3 and rand_core 0.10. Those builds line up with sspi, so we take them.

rsa is the exception, because its new line is still a release candidate. We use rsa 0.9, and the older digest, sha1 and rand_core it brings are confined to the code that signs and verifies RSA signatures.

A CI check builds justssh together with IronRDP and sspi to keep that true. We will move to rsa 0.10 when it is released as stable.

## Amendment (2026-10-21): stable-only is not enough; the coexistence build is the guarantee

The first coexistence build (#2) showed that pinning to stable releases does not prevent conflicts. The published `ironrdp` 0.17 contains `picky =7.0.0-rc.25`, which pins `curve25519-dalek =5.0.0-rc.1`. ed25519-dalek 3 requires the stable 5.0.0. Both versions fall in Cargo's 5.x range, so the two cannot be built together.

The general case: a dependency that pins a release candidate conflicts with anyone who has moved to the stable release in the same range. Avoiding release candidates ourselves cannot prevent that.

What guarantees coexistence is the coexistence build. It targets the IronRDP the broker will ship with, which is Devolutions/IronRDP master pinned to a revision (`66bfd60`, 2026-10-20, picky rc.26), not the latest crates.io release. That revision builds with justssh, and the pin is raised by hand.

## Amendment (2026-11-18): rsa stays on 0.9 until IronRDP's dependencies move

justssh 0.3.0 was published with rsa 0.10.0. main returns to rsa 0.9, and the next release takes it from there. rsa is again the one crate kept off the latest stable generation, and the body above holds for it except its last sentence: the trigger to move is no longer rsa 0.10's stable release.

The reason is where dependents are. crates.io, queried on 2026-11-18, counts these downloads over the last 90 days: rsa 0.9.10 56.9 million, 0.10.0-rc.18 4.2 million, 0.10.0 0.27 million. Of the first 300 reverse dependencies the crates.io API lists, 184 require 0.9 and 24 require 0.10.

rsa 0.9 is a Cargo range of its own, so it builds next to both kinds of rsa 0.10 user. picky and sspi, which IronRDP uses, pin `rsa =0.10.0-rc.18` and `pkcs1 =0.8.0-rc.4`. russh 0.65.2 requires `rsa ^0.10` and `pkcs1 ^0.8`, which resolve to the stable releases. rsa 0.10.0 conflicts with the first, because it requires pkcs1 0.8.0, which shares a range with that release candidate. A pin to the release candidate would conflict with the second.

The cost is RUSTSEC-2023-0071, which no 0.9 release fixes. The advisory is a timing leak in private-key operations; here those are RSA client authentication signatures and the broker's host key signatures. A 2048-bit signature measured about 1.2 ms on 0.9 against about 1.6 ms on 0.10 (release build, 200 signatures, 3 runs, #90).

rsa moves to 0.10 once picky and sspi require rsa 0.10.0 and IronRDP takes them. The coexistence build is back, and it is what shows that moment.
