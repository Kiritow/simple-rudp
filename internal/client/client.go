// Package client implements the private side of rudp: it asks a server to
// open public UDP ports and forwards what arrives there to local UDP services.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"simple-rudp/internal/protocol"
)

const (
	defaultKeepalive   = 10 * time.Second
	defaultPeerTimeout = 2 * time.Minute
	minBackoff         = time.Second
	maxBackoff         = 30 * time.Second
)

// Mapping forwards a public port on the server to a local UDP address.
type Mapping struct {
	RemotePort int    // port opened on the server; 0 lets the server pick
	LocalAddr  string // where traffic is delivered, e.g. "127.0.0.1:51820"
}

// ParseMapping parses "remotePort:localHost:localPort", e.g.
// "51820:127.0.0.1:51820" or "5353:[::1]:53".
func ParseMapping(s string) (Mapping, error) {
	remote, local, ok := strings.Cut(s, ":")
	if !ok {
		return Mapping{}, fmt.Errorf("invalid mapping %q: want remotePort:localHost:localPort", s)
	}
	port, err := strconv.ParseUint(remote, 10, 16)
	if err != nil {
		return Mapping{}, fmt.Errorf("invalid mapping %q: bad remote port", s)
	}
	if _, _, err := net.SplitHostPort(local); err != nil {
		return Mapping{}, fmt.Errorf("invalid mapping %q: %w", s, err)
	}
	return Mapping{RemotePort: int(port), LocalAddr: local}, nil
}

func (m Mapping) String() string { return strconv.Itoa(m.RemotePort) + ":" + m.LocalAddr }

// Config configures a Client.
type Config struct {
	ServerURL   string        // Control API root, e.g. "http://example.com:7000" or "https://example.com/rudp".
	TunnelAddr  string        // Server tunnel address; empty means the ServerURL host and the announced port.
	SecretKey   string        // Shared secret, the same as the server's. Required.
	Insecure    bool          // Skip TLS certificate verification, e.g. for the server's self-signed certificate.
	Mappings    []Mapping     // Ports to forward.
	Keepalive   time.Duration // Interval between Register packets once the tunnel is up.
	PeerTimeout time.Duration // Close a peer's local socket after this long without traffic.
	Logger      *slog.Logger
}

// Client keeps a set of mappings open on a server.
type Client struct {
	cfg  Config
	key  []byte
	base *url.URL
	hc   *http.Client
	log  *slog.Logger
}

// New returns a Client for cfg, filling in defaults for zero fields.
func New(cfg Config) (*Client, error) {
	if cfg.SecretKey == "" {
		return nil, errors.New("client: SecretKey is required")
	}
	if len(cfg.Mappings) == 0 {
		return nil, errors.New("client: no mappings configured")
	}
	base, err := ParseServerURL(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	if cfg.Keepalive <= 0 {
		cfg.Keepalive = defaultKeepalive
	}
	if cfg.PeerTimeout <= 0 {
		cfg.PeerTimeout = defaultPeerTimeout
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure}
	return &Client{
		cfg:  cfg,
		key:  []byte(cfg.SecretKey),
		base: base,
		hc:   &http.Client{Transport: tr, Timeout: protocol.RequestTimeout},
		log:  log,
	}, nil
}

// ParseServerURL parses the control API root. A bare "host:port" means
// "http://host:port".
func ParseServerURL(s string) (*url.URL, error) {
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("server URL %q: scheme must be http or https", s)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("server URL %q has no host", s)
	}
	return u, nil
}

// Run keeps every mapping up, reconnecting as needed, until ctx is done.
// Each mapping has its own session, so one failing mapping doesn't disturb
// the others.
func (c *Client) Run(ctx context.Context) error {
	defer c.hc.CloseIdleConnections()
	var wg sync.WaitGroup
	for _, m := range c.cfg.Mappings {
		wg.Go(func() { c.keepMapping(ctx, m) })
	}
	wg.Wait()
	return nil
}

// keepMapping runs m over and over, backing off between failed attempts.
func (c *Client) keepMapping(ctx context.Context, m Mapping) {
	log := c.log.With("mapping", m.String())
	backoff := minBackoff
	for {
		start := time.Now()
		err := c.runMapping(ctx, m, log)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > maxBackoff {
			backoff = minBackoff // it worked for a while; retry promptly
		}
		log.Warn("mapping down, retrying", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// runMapping establishes m once and relays traffic until the mapping fails.
func (c *Client) runMapping(ctx context.Context, m Mapping, log *slog.Logger) error {
	local, err := net.ResolveUDPAddr("udp", m.LocalAddr)
	if err != nil {
		return fmt.Errorf("resolve local address: %w", err)
	}
	sess, err := c.openSession(ctx)
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	// Ending the session frees its port at once, ready for the next attempt.
	defer sess.close()

	mapping, err := sess.openMapping(ctx, m.RemotePort)
	if err != nil {
		return fmt.Errorf("open mapping: %w", err)
	}
	addr := c.cfg.TunnelAddr
	if addr == "" {
		addr = net.JoinHostPort(c.base.Hostname(), strconv.Itoa(mapping.TunnelPort))
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("dial tunnel: %w", err)
	}
	log.Info("mapping opened", "public_port", mapping.Port, "tunnel", addr)

	t := &tunnel{
		conn:        conn,
		mapping:     mapping.ID,
		local:       local,
		keepalive:   c.cfg.Keepalive,
		peerTimeout: c.cfg.PeerTimeout,
		log:         log,
		peers:       make(map[uint32]*localPeer),
	}
	return t.run(ctx, func(ctx context.Context) error { return sess.keepAlive(ctx, log) })
}
