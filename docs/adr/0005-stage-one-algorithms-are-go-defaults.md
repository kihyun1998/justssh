# Stage-one algorithms are x/crypto/ssh's defaults, legacy included

Stage one negotiates exactly the default lists of x/crypto/ssh v0.55, including the entries Go itself marks insecure: `diffie-hellman-group14-sha1`, `hmac-sha1-96`, and `ssh-rsa` for host keys and public-key auth. `mlkem768x25519-sha256` is also in the list, and it is the preferred choice.

acwbroker's behaviour is the baseline. If an algorithm Go offers is dropped, the clients that have been connecting through it start failing, and the legacy clients in the interop matrix (MobaXterm 10.2 / SecureBlackbox) are why the broker exists in its current form.

Removing an algorithm is a later and deliberate step. It is not done here.

One exception was decided on #11: the client offers Go's default host key algorithms without the certificate algorithms and `ssh-dss`. acwbroker does not check upstream host keys, and an upstream with only a host certificate or only a DSA key is not reached.
