// bpc-p2p-relay is an explicit pilot listener, separate from legacy WGShim.
// No service installer or default public listener is enabled by this command.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/RomanKrike/bpc/internal/p2p"
)

func serve(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("bpc-p2p-relay", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:24446", "explicit TLS P2P listener")
	cluster := flags.String("cluster", "", "trusted cluster ID")
	issuer := flags.String("issuer-public-key", "", "Controller Ed25519 public key in canonical Base64")
	certFile := flags.String("tls-cert", "", "TLS certificate file")
	keyFile := flags.String("tls-key", "", "TLS key file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected relay arguments")
	}
	key, err := base64.StdEncoding.DecodeString(*issuer)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != *issuer {
		return errors.New("Controller public trust required")
	}
	relay, err := p2p.NewRelay(ed25519.PublicKey(key), *cluster, 0)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return errors.New("P2P relay TLS files unavailable")
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	return relay.Serve(ctx, listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := serve(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "P2P relay:", err)
		os.Exit(1)
	}
}
