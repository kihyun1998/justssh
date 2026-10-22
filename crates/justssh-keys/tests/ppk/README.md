# PPK fixtures

Throwaway test keys, copied from acwbroker's `internal/infrastructure/ppk/testdata`. None of them has ever been authorised anywhere but the test sshd.

| Files | Produced by |
| --- | --- |
| `<name>.openssh` | `ssh-keygen` (Windows OpenSSH), the source key |
| `<name>.ppk` | `WinSCP.com /keygen <name>.openssh /output=<name>.ppk` (WinSCP 6.5.6, which carries PuTTY's key code): PPK v3, Argon2id when encrypted; stored with LF line ends, as acwbroker keeps them |
| `puttygen_rsa_enc_v2.ppk`, `puttygen_rsa_enc_v3.ppk` | PuTTYgen (GUI), the same key saved as v2 and v3 |

Passphrases: `correct horse` for the `*-enc` files, `test1234` for the two PuTTYgen files.
