// Command go-interop runs one x/crypto/ssh v0.55 connection against justssh for its tests.
//
//	go-interop server -kex K -cipher C -mac M -hostkeys H -rekey N -serve -rejecthex H   listens on 127.0.0.1, prints the port, serves one connection
//	go-interop client -addr A -kex K -cipher C -mac M -hostkeyalgs A -rekey N -requests R -namehex H -printhostkey -openrefused   connects once
//	go-interop hostkey -type ed25519|rsa -out F   writes a host key as acwbroker does, prints its public key
//	go-interop readkey -in F -passphrase P   reads a private key file, prints its public key
//	go-interop readcert -hex H   parses a certificate blob as ParsePublicKey does
//	go-interop readline -in F   reads an authorized_keys certificate line as acwbroker does, prints the blob in hex
//
// Empty -kex, -cipher, -mac and -hostkeyalgs leave x/crypto/ssh's defaults; -rekey sets
// RekeyThreshold. With -requests the client sends R global requests of 1 KiB wanting a reply
// once authenticated; with -namehex the client sends a global request, opens a channel and sends a
// channel request all named by the hex bytes H, and fails unless each succeeds; with -serve the
// server stays until the client leaves, refusing requests. The server refuses every channel, with
// the message "no channels" or, with -rejecthex, the hex bytes H; with -openrefused the client
// opens a session channel, fails unless it is refused, and prints the reason and the message in
// hex. Both sides
// authenticate user "alice" with password "pw". The server's host keys are, by -hostkeys:
//
//	ed25519   ed25519 from a seed of 32 bytes of 7 (the default)
//	broker    that key, then a new RSA-2048 key offered only as ssh-rsa, as acwbroker does
//	all       that key, a new RSA-2048 key, and new ECDSA P-256, P-384 and P-521 keys
//
// The exit status is 0 once the connection is authenticated.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func list(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go-interop server|client [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "", "address to connect to (client)")
	kex := fs.String("kex", "", "key exchanges, comma-separated")
	cipher := fs.String("cipher", "", "ciphers, comma-separated")
	mac := fs.String("mac", "", "MACs, comma-separated")
	hostKeys := fs.String("hostkeys", "ed25519", "server host keys: ed25519, broker or all")
	hostKeyAlgs := fs.String("hostkeyalgs", "", "client host key algorithms, comma-separated")
	rekey := fs.Uint64("rekey", 0, "RekeyThreshold in bytes")
	requests := fs.Int("requests", 0, "global requests the client sends (client)")
	stay := fs.Bool("serve", false, "stay until the client leaves (server)")
	printHostKey := fs.Bool("printhostkey", false, "print the host key the server presented, as an authorized_keys line (client)")
	keyType := fs.String("type", "ed25519", "the host key to generate: ed25519 or rsa (hostkey)")
	out := fs.String("out", "", "the file to write (hostkey)")
	in := fs.String("in", "", "the key file to read (readkey)")
	passphrase := fs.String("passphrase", "", "the passphrase of the key file (readkey)")
	certHex := fs.String("hex", "", "the certificate blob to parse, in hex (readcert)")
	rejectHex := fs.String("rejecthex", "", "hex message the server refuses channels with (server)")
	openRefused := fs.Bool("openrefused", false, "open a session channel, print how it was refused (client)")
	nameHex := fs.String("namehex", "", "hex name of a global request, channel type and channel request the client sends, each wanting success (client)")
	_ = fs.Parse(os.Args[2:])
	algorithms := ssh.Config{
		KeyExchanges:   list(*kex),
		Ciphers:        list(*cipher),
		MACs:           list(*mac),
		RekeyThreshold: *rekey,
	}

	var err error
	switch os.Args[1] {
	case "server":
		var reject []byte
		if reject, err = hex.DecodeString(*rejectHex); err == nil {
			if *rejectHex == "" {
				reject = []byte("no channels")
			}
			err = serve(algorithms, *hostKeys, *stay, string(reject))
		}
	case "client":
		var name []byte
		if name, err = hex.DecodeString(*nameHex); err == nil {
			err = connect(*addr, algorithms, list(*hostKeyAlgs), *requests, string(name), *printHostKey, *openRefused)
		}
	case "hostkey":
		err = writeHostKey(*keyType, *out)
	case "readkey":
		err = readKey(*in, *passphrase)
	case "readcert":
		err = readCert(*certHex)
	case "readline":
		err = readLine(*in)
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// signers returns the host keys -hostkeys names, in the order they are added.
func signers(hostKeys string) ([]ssh.Signer, error) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	keys := []any{ed25519.NewKeyFromSeed(seed)}
	switch hostKeys {
	case "ed25519":
	case "broker", "all":
		r, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		keys = append(keys, r)
		if hostKeys == "all" {
			for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
				k, err := ecdsa.GenerateKey(c, rand.Reader)
				if err != nil {
					return nil, err
				}
				keys = append(keys, k)
			}
		}
	default:
		return nil, fmt.Errorf("unknown -hostkeys %q", hostKeys)
	}
	var out []ssh.Signer
	for _, k := range keys {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			return nil, err
		}
		if _, ok := k.(*rsa.PrivateKey); ok && hostKeys == "broker" {
			s, err = ssh.NewSignerWithAlgorithms(s.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
			if err != nil {
				return nil, err
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func serve(algorithms ssh.Config, hostKeys string, stay bool, reject string) error {
	keys, err := signers(hostKeys)
	if err != nil {
		return err
	}
	config := &ssh.ServerConfig{
		Config: algorithms,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "alice" && string(pass) == "pw" {
				return nil, nil
			}
			return nil, fmt.Errorf("wrong password")
		},
	}
	for _, k := range keys {
		config.AddHostKey(k)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		for c := range chans {
			_ = c.Reject(ssh.Prohibited, reject)
		}
	}()
	fmt.Println("authenticated")
	if stay {
		return sconn.Wait()
	}
	return sconn.Close()
}

func connect(addr string, algorithms ssh.Config, hostKeyAlgs []string, requests int, name string, printHostKey, openRefused bool) error {
	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if printHostKey {
		hostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fmt.Print(string(ssh.MarshalAuthorizedKey(key)))
			return nil
		}
	}
	config := &ssh.ClientConfig{
		Config:            algorithms,
		HostKeyAlgorithms: hostKeyAlgs,
		User:              "alice",
		Auth:              []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback:   hostKeyCallback,
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	cconn, _, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(reqs)
	fmt.Println("authenticated")
	payload := make([]byte, 1024)
	for i := 0; i < requests; i++ {
		if _, _, err := cconn.SendRequest("justssh-test@example.com", true, payload); err != nil {
			return fmt.Errorf("request %d: %w", i, err)
		}
	}
	if name != "" {
		if ok, _, err := cconn.SendRequest(name, true, nil); err != nil || !ok {
			return fmt.Errorf("global request %q: ok=%v err=%v", name, ok, err)
		}
		ch, chReqs, err := cconn.OpenChannel(name, nil)
		if err != nil {
			return fmt.Errorf("channel %q: %w", name, err)
		}
		go ssh.DiscardRequests(chReqs)
		if ok, err := ch.SendRequest(name, true, nil); err != nil || !ok {
			return fmt.Errorf("channel request %q: ok=%v err=%v", name, ok, err)
		}
		_ = ch.Close()
	}
	if openRefused {
		ch, _, err := cconn.OpenChannel("session", nil)
		var refused *ssh.OpenChannelError
		if !errors.As(err, &refused) {
			if ch != nil {
				_ = ch.Close()
			}
			return fmt.Errorf("session channel not refused: %v", err)
		}
		fmt.Printf("%d %x\n", refused.Reason, refused.Message)
	}
	return cconn.Close()
}

// writeHostKey generates a host key and writes it to out as acwbroker's hostkey.FileStore does
// (ssh.MarshalPrivateKey, comment "acwbroker"), then prints its public key.
func writeHostKey(keyType, out string) error {
	var priv any
	switch keyType {
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		priv = k
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		priv = k
	default:
		return fmt.Errorf("unknown key type %q", keyType)
	}
	block, err := ssh.MarshalPrivateKey(priv, "acwbroker")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return err
	}
	fmt.Print(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return nil
}

// readKey reads the private key file in, as acwbroker's upstream dialer does, and prints its
// public key.
func readKey(in, passphrase string) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(b)
	}
	if err != nil {
		return err
	}
	fmt.Print(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return nil
}

// readCert parses the certificate blob hexBlob as ssh.ParsePublicKey does.
func readCert(hexBlob string) error {
	blob, err := hex.DecodeString(hexBlob)
	if err != nil {
		return err
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return err
	}
	if _, ok := pub.(*ssh.Certificate); !ok {
		return fmt.Errorf("%T is a public key, not a certificate", pub)
	}
	return nil
}

// readLine reads the certificate line in the file in as acwbroker's upstream dialer does and
// prints the certificate blob in hex.
func readLine(in string) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("%T is a public key, not a certificate", pub)
	}
	fmt.Println(hex.EncodeToString(cert.Marshal()))
	return nil
}
