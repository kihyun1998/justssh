# PEM fixtures

Throwaway test keys, never authorised anywhere but the test sshd. Our code wrote none of them.

| Files | Produced by |
| --- | --- |
| `rsa-pkcs1`, `rsa-pkcs1-aes128`, `ec256-sec1`, `ec384-sec1-aes128`, `ec521-sec1` | `ssh-keygen -m PEM` (OpenSSH 10.0; `-N` gives AES-128-CBC) |
| `rsa-pkcs8`, `ec256-pkcs8` | `ssh-keygen -m PKCS8` |
| `ed25519-pkcs8`, `x25519-pkcs8` | `openssl genpkey` (OpenSSL 3.2.4) |
| `rsa-pkcs1-des`, `rsa-pkcs1-des3` | `openssl rsa -traditional -des` (legacy provider) / `-des3` from `rsa-pkcs1`, so their `.pub` is its |
| `ec256-sec1-aes192`, `ec256-sec1-aes256` | `openssl ec -aes192` / `-aes256` from `ec256-sec1` |
| `rsa-pkcs1-3primes` | `openssl genpkey -pkeyopt rsa_keygen_primes:3`, then `openssl rsa -traditional` |
| `rsa-pkcs8-encrypted` | `openssl pkcs8 -topk8` from `rsa-pkcs8` |
| `dsa-pkcs8`, `dsa` | `openssl genpkey` on 1024/160 parameters (`dsa_paramgen_bits:1024`, `dsa_paramgen_q_bits:160`, a size x/crypto/ssh reads), and `openssl pkey -traditional` from it |
| `<name>.pub` | `ssh-keygen -y` of each file it reads |

Passphrase `correct horse` for every encrypted file.
