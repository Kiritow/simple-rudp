// Command rudp is a reverse UDP port forwarder.
//
// Run the server on a host with a public address and the client next to the
// UDP service to expose, both with the same secret key:
//
//	export RUDP_SECRET=$(rudp keygen)
//	rudp server -control :7000 -tunnel :7001
//	rudp client -server http://example.com:7000 -map 51820:127.0.0.1:51820
//
// Datagrams sent to example.com:51820 then reach 127.0.0.1:51820 on the
// client's host, and replies travel back the same way. Settings can also come
// from a YAML file given with -config; see the examples directory.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"simple-rudp/internal/client"
	"simple-rudp/internal/server"
)

const usage = `usage:
  rudp server [-config file] [flags]   expose ports requested by clients
  rudp client [-config file] [flags]   forward server ports to local UDP services
  rudp keygen                          print a random secret key

Run "rudp server -h" or "rudp client -h" for flags.
Settings come from, in increasing order of precedence: defaults, the YAML
file given with -config, $RUDP_SECRET (for the secret key), and flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "server":
		err = runServer(ctx, args)
	case "client":
		err = runClient(ctx, args)
	case "keygen":
		fmt.Println(rand.Text()) // 130 random bits, base32
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "rudp: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "rudp:", err)
		os.Exit(1)
	}
}

func runServer(ctx context.Context, args []string) error {
	c := defaultServerConfig()
	if err := parseArgs("rudp server", args, &c, &c.Secret, defineServerFlags, os.Stderr); err != nil {
		return err
	}
	if c.Secret == "" {
		return errors.New("a secret key is required: use -secret, RUDP_SECRET or the config file (try: rudp keygen)")
	}
	cfg := server.Config{
		ControlAddr:    c.Control,
		TunnelAddr:     c.Tunnel,
		BindHost:       c.Bind,
		SecretKey:      c.Secret,
		AllowPorts:     server.PortRanges(c.AllowPorts),
		SessionTimeout: c.SessionTimeout,
		PeerTimeout:    c.PeerTimeout,
		Logger:         newLogger(c.Verbose),
	}
	if c.TLS {
		var err error
		if cfg.TLS, err = server.SelfSignedTLS(); err != nil {
			return fmt.Errorf("generate certificate: %w", err)
		}
	}
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	return srv.ListenAndServe(ctx)
}

func runClient(ctx context.Context, args []string) error {
	c := defaultClientConfig()
	if err := parseArgs("rudp client", args, &c, &c.Secret, defineClientFlags, os.Stderr); err != nil {
		return err
	}
	if c.Server == "" || len(c.Mappings) == 0 {
		return errors.New("a server URL and at least one mapping are required: use -server and -map, or the config file")
	}
	if c.Secret == "" {
		return errors.New("a secret key is required: use -secret, RUDP_SECRET or the config file")
	}
	mappings := make([]client.Mapping, len(c.Mappings))
	for i, m := range c.Mappings {
		mappings[i] = client.Mapping(m)
	}
	cl, err := client.New(client.Config{
		ServerURL:   c.Server,
		TunnelAddr:  c.Tunnel,
		SecretKey:   c.Secret,
		Insecure:    c.Insecure,
		Mappings:    mappings,
		Keepalive:   c.Keepalive,
		PeerTimeout: c.PeerTimeout,
		Logger:      newLogger(c.Verbose),
	})
	if err != nil {
		return err
	}
	return cl.Run(ctx)
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
