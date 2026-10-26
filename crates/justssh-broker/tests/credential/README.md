# Credential fixtures

Throwaway keys, never authorised anywhere.

| Files | Produced by |
| --- | --- |
| `user`, `user.pub` | `ssh-keygen -t ed25519 -N ""` (OpenSSH 10.0p2) |
| `user-cert.pub`, `other-cert.pub` | `ssh-keygen -s` with a throwaway CA, principal `acw`, valid always: for `user`, and for another key since discarded |
| `damaged-mac.ppk`, `version4.ppk`, `dss.ppk`, `argon2d.ppk`, `unknown-kdf.ppk`, `costly.ppk`, `aes128.ppk` | `justssh-keys/tests/ppk/ed25519.ppk` or `ed25519-enc.ppk` with one header edited: the MAC's first digit, the version, the algorithm, the key derivation (`Argon2d`, `Argon2x`), `Argon2-Memory: 4194304`, `Encryption: aes128-cbc` |
| `garbage` | the text `not a key` |
| `check.tsv` | acwbroker 19d90c5's own `upstream.Check` and `refusalFor` over each case, run under `go test -overlay` |
