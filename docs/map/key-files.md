# Key files

How `justssh-keys` (`crates/justssh-keys/src/`) reads and writes private key files, and what to watch when changing it.

## OpenSSH keys are read as x/crypto/ssh reads them

An OpenSSH private key file (`PROTOCOL.key`) is read with the limits of x/crypto/ssh's `parseOpenSSHPrivateKey` (`keys.go`), since acwbroker reads its host key files and upstream keys with it: one key per file, the bcrypt KDF with at most 2048 rounds (`maxRounds`), and AES-256 in CTR or CBC mode. Other ciphers, such as `aes256-gcm@openssh.com` and `chacha20-poly1305@openssh.com` that `ssh-keygen -Z` can choose, are refused by name before anything is derived; Go cannot read them either. RSA keys are held to Go's bounds: a modulus of at most 16384 bits, primes of at most 8192, an exponent that is odd, at least 3 and at most 24 bits; a private exponent longer than the modulus is refused before any arithmetic, which bounds the work a hostile file can cause and changes no outcome, so no test sees it. Bytes after the private section are ignored, as Go's `Rest` field takes them, and the armor must start a line, as Go's `pem.Decode` wants. An empty passphrase counts as none, as acwbroker passes one only when it is set, and a passphrase given for a key that is not encrypted is refused, as Go's `ParsePrivateKeyWithPassphrase` refuses it.

Two things Go reads are refused here. The file's public halves must match its private key, the outer public key and, for ed25519, the public key stored after the seed, where Go compares the public point only for ECDSA; `ssh-keygen` never writes halves that disagree. And an RSA key under 1024 bits is refused, as the core refuses it (`PrivateKey::rsa`).

2048 rounds of bcrypt-pbkdf take seconds, and many times that unoptimised, so `bcrypt-pbkdf` and `blowfish` are built optimised in dev builds (workspace `Cargo.toml`); the test that reads a key at the round limit took 65 s without and 18 s with (measured on #21).

## Keys are written as acwbroker writes its host key

`KeyFile::to_openssh` writes an unencrypted file of the same structure as x/crypto/ssh's `MarshalPrivateKey`, which is how acwbroker writes `hostkey` and `hostkey-rsa` (`internal/infrastructure/hostkey/file_store.go`), so a Rust broker and a Go one can take each other's files. The check numbers are random and the lines 70 columns wide, as `ssh-keygen` writes them, where Go's `pem.EncodeToMemory` writes 64, so the bytes differ from Go's. The buffers this crate holds key material in zeroize on drop, and the one the file is assembled in zeroizes each allocation it outgrows; `bcrypt-pbkdf` and `cbc` are built with their `zeroize` features. What the RSA arithmetic leaves is not reached: rsa 0.9 and the inverse taken for the CRT coefficient make big integer temporaries that are not wiped, as the core's RSA signing does. The coefficient is taken from the primes alone, not by building a second key.

Generating a host key and publishing it exclusively, as acwbroker's `FileStore.generate` does, is the consumer's: the maintainer chose on #21 to keep the library to reading and writing. Writing an encrypted file is not done.

## Certificates come as an authorized_keys line

`certificate_from_line` reads a certificate as acwbroker does, with x/crypto/ssh's `ParseAuthorizedKey` (`internal/infrastructure/upstream/ssh_dialer.go`): the first line holding a key, past blank and `#` lines, its type taken first as the line's first field and otherwise after an options field, which runs to the first space or tab outside double quotes; the declared type must be the blob's, and the blob must be a certificate, which acwbroker requires next. White space is trimmed as Go's `bytes.TrimSpace` trims it, Unicode spaces included, and the base64 is decoded as Go's `StdEncoding` decodes it, taking unused bits in the last character. A line that does not parse is passed over for the next, as Go passes it over. Two cases differ from Go, both needing more than one line, where acwbroker passes one: the certificate's fields are checked when the key is put under it (`PrivateKey::with_certificate`, `user-authentication.md`), so a broken certificate on an earlier line fails there rather than giving way to a later one; and a plain key's line ends the search with `UnsupportedKeyType` without its key being checked, where Go would pass over a plain key that does not parse. `go_reads_each_certificate_line_as_justssh_keys_does` gives Go and this crate the same 16 lines and compares what each reads, including a certificate line commented out, which both refuse (#47).

## What is not read yet

PEM keys (PKCS#1, PKCS#8, SEC1, legacy encrypted PEM) and PuTTY's PPK, which acwbroker reads (`parseKey`, `internal/infrastructure/ppk`), were split from #21 by the maintainer (#45, #46).

## What the proofs cover

The fixtures in `crates/justssh-keys/tests/keys/` were made by `ssh-keygen` 10.0, each with its own `.pub` line as the expected public key, and are kept byte for byte (`.gitattributes`). Against real peers: a Go client sees the same host key from a server built on a host key file Go's `MarshalPrivateKey` wrote, ed25519 and the `ssh-rsa`-only RSA alike; Go and `ssh-keygen -y` read every file written here; and sshd accepts all seven fixtures as client keys (`crates/justssh-tokio/tests/go.rs`, `sshd.rs`).
