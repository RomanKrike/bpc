package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/RomanKrike/bpc/internal/wgshim"
)

const version = "0.8.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "client":
		runClient(os.Args[2:])
	case "server":
		runServer(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Printf("bpc-wgshim %s\n", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:24081", "local UDP endpoint used by WireGuard")
	server := fs.String("server", "", "BPC WGShim server host:port")
	keyFile := fs.String("key-file", "", "file containing a base64 32-byte PSK")
	paddingMin := fs.Int("padding-min", 0, "minimum random padding bytes per packet")
	paddingMax := fs.Int("padding-max", 31, "maximum random padding bytes per packet")
	statsInterval := fs.Duration("stats-interval", 30*time.Second, "stats log interval; 0 disables")
	_ = fs.Parse(args)
	if *server == "" || *keyFile == "" {
		fs.Usage()
		os.Exit(2)
	}

	psk := mustLoadPSK(*keyFile)
	tx := mustCodec(psk, wgshim.ClientToServer, *paddingMin, *paddingMax)
	rx := mustCodec(psk, wgshim.ServerToClient, *paddingMin, *paddingMax)
	logger := log.New(os.Stdout, "bpc-wgshim ", log.LstdFlags|log.LUTC)
	logger.Printf("starting client listen=%s server=%s padding=%d..%d", *listen, *server, *paddingMin, *paddingMax)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := wgshim.RunClient(ctx, wgshim.ClientConfig{
		LocalListen:   *listen,
		Server:        *server,
		TX:            tx,
		RX:            rx,
		Logger:        logger,
		StatsInterval: *statsInterval,
	}); err != nil {
		logger.Fatal(err)
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:24443", "outer UDP listen address")
	target := fs.String("target", "", "WireGuard UDP target host:port")
	keyFile := fs.String("key-file", "", "file containing a base64 32-byte PSK")
	paddingMin := fs.Int("padding-min", 0, "minimum random padding bytes per packet")
	paddingMax := fs.Int("padding-max", 31, "maximum random padding bytes per packet")
	statsInterval := fs.Duration("stats-interval", 30*time.Second, "stats log interval; 0 disables")
	_ = fs.Parse(args)
	if *target == "" || *keyFile == "" {
		fs.Usage()
		os.Exit(2)
	}

	psk := mustLoadPSK(*keyFile)
	rx := mustCodec(psk, wgshim.ClientToServer, *paddingMin, *paddingMax)
	tx := mustCodec(psk, wgshim.ServerToClient, *paddingMin, *paddingMax)
	logger := log.New(os.Stdout, "bpc-wgshim ", log.LstdFlags|log.LUTC)
	logger.Printf("starting server listen=%s target=%s padding=%d..%d", *listen, *target, *paddingMin, *paddingMax)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := wgshim.RunServer(ctx, wgshim.ServerConfig{
		Listen:        *listen,
		Target:        *target,
		RX:            rx,
		TX:            tx,
		Logger:        logger,
		StatsInterval: *statsInterval,
	}); err != nil {
		logger.Fatal(err)
	}
}

func mustLoadPSK(path string) []byte {
	key, err := wgshim.LoadPSK(path)
	if err != nil {
		log.Fatalf("load key: %v", err)
	}
	return key
}

func mustCodec(psk []byte, direction wgshim.Direction, paddingMin, paddingMax int) *wgshim.Codec {
	key, err := wgshim.DeriveKey(psk, direction)
	if err != nil {
		log.Fatalf("derive key: %v", err)
	}
	codec, err := wgshim.NewCodec(key, paddingMin, paddingMax)
	if err != nil {
		log.Fatalf("create codec: %v", err)
	}
	return codec
}

func usage() {
	fmt.Fprintln(os.Stderr, `BPC WGShim - low-latency authenticated UDP wrapper for WireGuard

Usage:
  bpc-wgshim client --server HOST:PORT --key-file FILE [options]
  bpc-wgshim server --target HOST:PORT --key-file FILE [options]
  bpc-wgshim version

The client listens on 127.0.0.1:24081 by default. Point the normal WireGuard
peer Endpoint at that address. WGShim carries the datagrams to the BPC server,
which authenticates/decrypts them and forwards them to the configured WireGuard
target. No WireGuard cryptography is modified.`)
}
