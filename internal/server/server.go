// Package server implements the public side of rudp: it serves the HTTP(S)
// control API, opens the UDP ports authenticated clients ask for, and relays
// datagrams between those ports and the clients' tunnel sockets.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"simple-rudp/internal/protocol"
)

const (
	defaultAuthTimeout    = 60 * time.Second
	defaultSessionTimeout = 30 * time.Second
	defaultPeerTimeout    = 2 * time.Minute
	shutdownTimeout       = 5 * time.Second
)

// Config configures a Server.
type Config struct {
	ControlAddr    string        // TCP address of the control API, e.g. ":7000".
	TunnelAddr     string        // UDP address clients send tunnel traffic to, e.g. ":7001".
	BindHost       string        // Host to open public ports on; empty means all interfaces.
	SecretKey      string        // Shared secret clients must prove they know. Required.
	TLS            *tls.Config   // If set, the control API is served over HTTPS.
	AllowPorts     PortRanges    // Public ports clients may ask for; empty allows any.
	AuthTimeout    time.Duration // Drop sessions not authenticated this long after creation.
	SessionTimeout time.Duration // Close sessions (and their mappings) after this long without a request.
	PeerTimeout    time.Duration // Forget a WAN peer after this long without traffic.
	Logger         *slog.Logger
}

// Server relays UDP traffic between public ports and clients.
type Server struct {
	cfg Config
	key []byte
	log *slog.Logger

	tun        *net.UDPConn // shared tunnel socket, set by Serve
	tunnelPort int
	running    sync.WaitGroup // mapping goroutines

	ctlMu   sync.Mutex
	closing bool                     // shutting down: no new sessions or mappings
	pending map[protocol.ID]*session // not yet authenticated
	active  map[protocol.ID]*session

	mu       sync.RWMutex
	mappings map[protocol.ID]*mapping
	byAddr   map[netip.AddrPort]*mapping // keyed by the client's tunnel address
}

// New returns a Server for cfg, filling in defaults for zero fields.
func New(cfg Config) (*Server, error) {
	if cfg.SecretKey == "" {
		return nil, errors.New("server: SecretKey is required")
	}
	if cfg.AuthTimeout <= 0 {
		cfg.AuthTimeout = defaultAuthTimeout
	}
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = defaultSessionTimeout
	}
	if cfg.PeerTimeout <= 0 {
		cfg.PeerTimeout = defaultPeerTimeout
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		key:      []byte(cfg.SecretKey),
		log:      log,
		pending:  make(map[protocol.ID]*session),
		active:   make(map[protocol.ID]*session),
		mappings: make(map[protocol.ID]*mapping),
		byAddr:   make(map[netip.AddrPort]*mapping),
	}, nil
}

// ListenAndServe listens on cfg.ControlAddr and cfg.TunnelAddr, then calls Serve.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.ControlAddr)
	if err != nil {
		return err
	}
	pc, err := lc.ListenPacket(ctx, "udp", s.cfg.TunnelAddr)
	if err != nil {
		ln.Close()
		return err
	}
	return s.Serve(ctx, ln, pc.(*net.UDPConn))
}

// Serve serves the control API on ln and tunnel traffic on tun until ctx is
// done, then closes both and waits for every mapping to shut down. It
// returns nil once ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener, tun *net.UDPConn) error {
	s.tun = tun
	s.tunnelPort = tun.LocalAddr().(*net.UDPAddr).Port
	hs := &http.Server{
		Handler:           s.routes(),
		TLSConfig:         s.cfg.TLS,
		ReadHeaderTimeout: protocol.RequestTimeout,
		ReadTimeout:       protocol.RequestTimeout,
		WriteTimeout:      protocol.RequestTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	scheme := "http"
	if s.cfg.TLS != nil {
		scheme = "https"
	}
	s.log.Info("listening", "control", scheme+"://"+ln.Addr().String(), "tunnel", tun.LocalAddr().String())

	bgCtx, stopBg := context.WithCancel(context.Background())
	var bg sync.WaitGroup
	bg.Go(s.serveTunnel)
	bg.Go(func() { s.expireSessions(bgCtx) })

	errc := make(chan error, 1)
	go func() {
		if s.cfg.TLS != nil {
			errc <- hs.ServeTLS(ln, "", "") // certificates come from TLSConfig
		} else {
			errc <- hs.Serve(ln)
		}
	}()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}

	// Let requests in flight finish, then end every session and mapping.
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	if hs.Shutdown(sctx) != nil {
		hs.Close()
	}
	cancel()
	if err == nil {
		err = <-errc
	}
	stopBg()
	s.closeAllSessions()
	s.running.Wait()
	tun.Close()
	bg.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) unregister(m *mapping) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.mappings, m.id)
	if addr := m.client.Load(); addr != nil && s.byAddr[*addr] == m {
		delete(s.byAddr, *addr)
	}
}

// bindClient records addr as the tunnel address of mapping id. It reports
// whether the mapping exists.
func (s *Server) bindClient(id protocol.ID, addr netip.AddrPort) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.mappings[id]
	if m == nil {
		return false
	}
	old := m.client.Load()
	if old != nil && *old == addr {
		return true
	}
	if old != nil && s.byAddr[*old] == m {
		delete(s.byAddr, *old)
	}
	m.client.Store(&addr)
	s.byAddr[addr] = m
	if old == nil {
		m.log.Info("tunnel up", "port", m.port, "tunnel_addr", addr)
	} else {
		m.log.Info("tunnel address changed", "port", m.port, "from", *old, "to", addr)
	}
	return true
}

var ackPacket = protocol.AppendAck(nil)

// serveTunnel handles everything clients send to the tunnel socket.
func (s *Server) serveTunnel() {
	buf := make([]byte, protocol.MaxDatagram)
	for {
		n, from, err := s.tun.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Debug("tunnel read", "err", err)
			continue
		}
		pkt := buf[:n]

		if peer, payload, ok := protocol.ParseData(pkt); ok {
			s.mu.RLock()
			m := s.byAddr[from]
			s.mu.RUnlock()
			if m != nil {
				m.deliver(peer, payload)
			}
			continue
		}
		// Unknown mappings get no answer, so the port can't be probed for them.
		if id, ok := protocol.ParseRegister(pkt); ok && s.bindClient(id, from) {
			if _, err := s.tun.WriteToUDPAddrPort(ackPacket, from); err != nil {
				s.log.Debug("tunnel write", "err", err)
			}
		}
	}
}
