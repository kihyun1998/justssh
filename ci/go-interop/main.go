// Command go-interop runs one x/crypto/ssh v0.55 connection against justssh for its tests.
//
//	go-interop server -kex K -cipher C -mac M   listens on 127.0.0.1, prints the port, serves one connection
//	go-interop client -addr A -kex K -cipher C -mac M   connects once
//
// Empty -kex, -cipher and -mac leave x/crypto/ssh's defaults. Both sides authenticate user
// "alice" with password "pw"; the server's host key is ed25519 from a seed of 32 bytes of 7.
// The exit status is 0 once the connection is authenticated.
package main

import (
	"crypto/ed25519"
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
	_ = fs.Parse(os.Args[2:])
	algorithms := ssh.Config{KeyExchanges: list(*kex), Ciphers: list(*cipher), MACs: list(*mac)}

	var err error
	switch os.Args[1] {
	case "server":
		err = serve(algorithms)
	case "client":
		err = connect(*addr, algorithms)
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(algorithms ssh.Config) error {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
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
	config.AddHostKey(signer)
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
			_ = c.Reject(ssh.Prohibited, "no channels")
		}
	}()
	fmt.Println("authenticated")
	return sconn.Close()
}

func connect(addr string, algorithms ssh.Config) error {
	config := &ssh.ClientConfig{
		Config:          algorithms,
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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
	return cconn.Close()
}
