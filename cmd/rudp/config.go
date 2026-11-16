package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"go.yaml.in/yaml/v3"

	"simple-rudp/internal/client"
	"simple-rudp/internal/server"
)

// serverConfig holds the settings of "rudp server". Each YAML key matches
// the flag of the same name, with "-" written as "_".
type serverConfig struct {
	Control        string        `yaml:"control"`
	Tunnel         string        `yaml:"tunnel"`
	Bind           string        `yaml:"bind"`
	Secret         string        `yaml:"secret"`
	TLS            bool          `yaml:"tls"`
	AllowPorts     portRanges    `yaml:"allow_ports"`
	SessionTimeout time.Duration `yaml:"session_timeout"`
	PeerTimeout    time.Duration `yaml:"peer_timeout"`
	Verbose        bool          `yaml:"verbose"`
}

func defaultServerConfig() serverConfig {
	return serverConfig{
		Control:        ":7000",
		Tunnel:         ":7001",
		SessionTimeout: 30 * time.Second,
		PeerTimeout:    2 * time.Minute,
	}
}

func defineServerFlags(fs *flag.FlagSet, c *serverConfig) {
	fs.StringVar(&c.Control, "control", c.Control, "TCP `address` of the HTTP control API")
	fs.StringVar(&c.Tunnel, "tunnel", c.Tunnel, "UDP `address` for tunnel traffic from clients")
	fs.StringVar(&c.Bind, "bind", c.Bind, "`host` to open public ports on (default all interfaces)")
	fs.StringVar(&c.Secret, "secret", c.Secret, "shared secret `key` (default $RUDP_SECRET)")
	fs.BoolVar(&c.TLS, "tls", c.TLS, "serve the control API over HTTPS with a self-signed certificate")
	fs.Var(newListFlag(&c.AllowPorts, parsePortRanges), "allow-ports", "`ports` clients may open, e.g. 10000-20000,51820 (default any)")
	fs.DurationVar(&c.SessionTimeout, "session-timeout", c.SessionTimeout, "close a client's ports after this `long` without a heartbeat")
	fs.DurationVar(&c.PeerTimeout, "peer-timeout", c.PeerTimeout, "forget WAN peers idle for this `long`")
	fs.BoolVar(&c.Verbose, "v", c.Verbose, "log every peer and packet error")
}

// clientConfig holds the settings of "rudp client". Each YAML key matches
// the flag of the same name, with "-" written as "_"; "mappings" holds the
// -map values.
type clientConfig struct {
	Server      string        `yaml:"server"`
	Tunnel      string        `yaml:"tunnel"`
	Secret      string        `yaml:"secret"`
	Insecure    bool          `yaml:"insecure"`
	Mappings    []mapping     `yaml:"mappings"`
	Keepalive   time.Duration `yaml:"keepalive"`
	PeerTimeout time.Duration `yaml:"peer_timeout"`
	Verbose     bool          `yaml:"verbose"`
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		Keepalive:   10 * time.Second,
		PeerTimeout: 2 * time.Minute,
	}
}

func defineClientFlags(fs *flag.FlagSet, c *clientConfig) {
	fs.StringVar(&c.Server, "server", c.Server, "control API `URL`, e.g. http://example.com:7000 or https://example.com/rudp (required)")
	fs.StringVar(&c.Tunnel, "tunnel", c.Tunnel, "server tunnel `address` (default: server URL host, port announced by the server)")
	fs.StringVar(&c.Secret, "secret", c.Secret, "shared secret `key` (default $RUDP_SECRET)")
	fs.BoolVar(&c.Insecure, "insecure", c.Insecure, "accept any TLS certificate, e.g. the server's self-signed one")
	fs.Var(newListFlag(&c.Mappings, parseMapping), "map", "forward `remotePort:localHost:localPort` (repeatable)")
	fs.DurationVar(&c.Keepalive, "keepalive", c.Keepalive, "`interval` between tunnel keepalives")
	fs.DurationVar(&c.PeerTimeout, "peer-timeout", c.PeerTimeout, "close local sockets of peers idle for this `long`")
	fs.BoolVar(&c.Verbose, "v", c.Verbose, "log every peer and packet error")
}

// parseArgs fills cfg from, in increasing order of precedence: its current
// (default) values, the YAML file named by -config, $RUDP_SECRET (for the
// secret only), and the other flags. Warnings go to stderr.
func parseArgs[C any](name string, args []string, cfg *C, secret *string, define func(*flag.FlagSet, *C), stderr io.Writer) error {
	defaults := *cfg
	parse := func() (*flag.FlagSet, string, error) {
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("config", "", "YAML config `file`; flags override its settings")
		define(fs, cfg) // flags default to cfg's current values
		if err := fs.Parse(args); err != nil {
			return nil, "", err
		}
		if fs.NArg() > 0 {
			return nil, "", fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return fs, *path, nil
	}

	fs, path, err := parse()
	if err != nil {
		return err
	}
	secretInFile := false
	if path != "" {
		*cfg = defaults
		if err := loadYAML(path, cfg); err != nil {
			return err
		}
		secretInFile = *secret != ""
		// Parse again, now with the file's settings as defaults, so that
		// the flags actually given override them.
		if fs, _, err = parse(); err != nil {
			return err
		}
	}

	switch env := os.Getenv("RUDP_SECRET"); {
	case isSet(fs, "secret"):
	case env != "":
		*secret = env
	case secretInFile:
		warnIfShared(path, stderr)
	}
	return nil
}

// loadYAML decodes the YAML file at path into v, rejecting unknown keys.
// An empty file changes nothing.
func loadYAML(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config %s: %w", path, err)
	}
	return nil
}

// warnIfShared warns when a config file holding the secret key is
// accessible to other users.
func warnIfShared(path string, w io.Writer) {
	if runtime.GOOS == "windows" {
		return // permission bits don't mean the same there
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(w, "rudp: warning: %s holds the secret key but other users can access it (chmod 600 %[1]s)\n", path)
	}
}

func isSet(fs *flag.FlagSet, name string) (set bool) {
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// listFlag is a repeatable flag for a list setting. Its first use replaces
// the list (as loaded from a config file); further uses append to it.
type listFlag[S ~[]E, E any] struct {
	list    *S
	parse   func(string) (S, error)
	touched bool
}

func newListFlag[S ~[]E, E any](list *S, parse func(string) (S, error)) *listFlag[S, E] {
	return &listFlag[S, E]{list: list, parse: parse}
}

func (f *listFlag[S, E]) Set(s string) error {
	v, err := f.parse(s)
	if err != nil {
		return err
	}
	if !f.touched {
		*f.list, f.touched = nil, true
	}
	*f.list = append(*f.list, v...)
	return nil
}

func (f *listFlag[S, E]) String() string { return "" }

// portRanges is server.PortRanges as written in a config file: either a
// string like "10000-20000,51820" or a list of ports and ranges.
type portRanges server.PortRanges

func parsePortRanges(s string) (portRanges, error) {
	var r server.PortRanges
	err := r.Set(s)
	return portRanges(r), err
}

func (p *portRanges) UnmarshalYAML(n *yaml.Node) error {
	var items []*yaml.Node
	switch n.Kind {
	case yaml.ScalarNode:
		items = []*yaml.Node{n}
	case yaml.SequenceNode:
		items = n.Content
	default:
		return fmt.Errorf("line %d: allow_ports must be a port range or a list of them", n.Line)
	}
	var r server.PortRanges
	for _, item := range items {
		if item.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: allow_ports entries must be ports or port ranges", item.Line)
		}
		if err := r.Set(item.Value); err != nil {
			return fmt.Errorf("line %d: %w", item.Line, err)
		}
	}
	*p = portRanges(r)
	return nil
}

// mapping is client.Mapping as written in a config file: either the -map
// form "remotePort:localHost:localPort" or {remote_port, local}.
type mapping client.Mapping

func parseMapping(s string) ([]mapping, error) {
	m, err := client.ParseMapping(s)
	return []mapping{mapping(m)}, err
}

func (m *mapping) UnmarshalYAML(n *yaml.Node) error {
	s := n.Value
	if n.Kind != yaml.ScalarNode {
		var v struct {
			RemotePort *int   `yaml:"remote_port"`
			Local      string `yaml:"local"`
		}
		if err := n.Decode(&v); err != nil {
			return err
		}
		if v.RemotePort == nil || v.Local == "" {
			return fmt.Errorf("line %d: a mapping needs remote_port and local", n.Line)
		}
		s = fmt.Sprintf("%d:%s", *v.RemotePort, v.Local)
	}
	cm, err := client.ParseMapping(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*m = mapping(cm)
	return nil
}
