# Host key fixtures

| Files | Produced by |
| --- | --- |
| `hostkey-rsa`, `hostkey-rsa.pub` | Go 1.26.3 and x/crypto v0.55: `rsa.GenerateKey(rand.Reader, 2048)`, then `ssh.MarshalPrivateKey(k, "acwbroker")` and `pem.EncodeToMemory`, as acwbroker's `hostkey.FileStore.generate` writes `hostkey-rsa`; the `.pub` is `ssh.MarshalAuthorizedKey` of its public key |
