package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"simple-rudp/internal/protocol"
)

// mapping is a public UDP port tied to one client's tunnel.
type mapping struct {
	id          protocol.ID
	port        int
	pub         *net.UDPConn // public socket WAN peers talk to
	tun         *net.UDPConn // the server's shared tunnel socket
	peerTimeout time.Duration
	log         *slog.Logger
	cancel      context.CancelFunc // closes the mapping

	client atomic.Pointer[netip.AddrPort] // client's tunnel address; nil until it registers

	mu     sync.Mutex
	nextID uint32
	peers  map[uint32]*peer
	byAddr map[netip.AddrPort]*peer
}

// peer is a WAN address that sent traffic to the public port.
type peer struct {
	id       uint32
	addr     netip.AddrPort
	lastSeen atomic.Int64 // unix nanoseconds
}

func (p *peer) touch() { p.lastSeen.Store(time.Now().UnixNano()) }

// openMapping opens a public port owned by sess. On failure it also returns
// the HTTP status to report.
func (s *Server) openMapping(sess *session, port int) (*mapping, int, error) {
	if !s.cfg.AllowPorts.Allows(port) {
		return nil, http.StatusForbidden, fmt.Errorf("port %d not allowed", port)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort(s.cfg.BindHost, strconv.Itoa(port)))
	if err != nil {
		cancel()
		if errors.Is(err, syscall.EADDRINUSE) {
			return nil, http.StatusConflict, err
		}
		return nil, http.StatusInternalServerError, err
	}
	pub := pc.(*net.UDPConn)
	m := &mapping{
		id:          protocol.NewID(),
		port:        pub.LocalAddr().(*net.UDPAddr).Port,
		pub:         pub,
		tun:         s.tun,
		peerTimeout: s.cfg.PeerTimeout,
		log:         sess.log,
		cancel:      cancel,
		peers:       make(map[uint32]*peer),
		byAddr:      make(map[netip.AddrPort]*peer),
	}

	// Once shutdown has begun, no mapping goroutine may start: Serve is
	// about to wait for them.
	s.ctlMu.Lock()
	if s.closing {
		s.ctlMu.Unlock()
		cancel()
		pub.Close()
		return nil, http.StatusServiceUnavailable, errors.New("server shutting down")
	}
	s.running.Add(1)
	s.ctlMu.Unlock()

	s.mu.Lock()
	s.mappings[m.id] = m
	s.mu.Unlock()
	context.AfterFunc(ctx, func() {
		s.unregister(m)
		pub.Close()
	})
	if !sess.addMapping(m) {
		cancel()
		s.running.Done()
		return nil, http.StatusNotFound, errSessionClosed
	}
	go func() {
		defer s.running.Done()
		m.serve(ctx)
	}()
	m.log.Info("mapping opened", "port", m.port)
	return m, 0, nil
}

// serve relays WAN traffic into the tunnel until the mapping is closed.
func (m *mapping) serve(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { m.expirePeers(ctx) })

	buf := make([]byte, protocol.DataHeaderLen+protocol.MaxDatagram)
	for {
		n, from, err := m.pub.ReadFromUDPAddrPort(buf[protocol.DataHeaderLen:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				m.log.Info("mapping closed", "port", m.port)
				return
			}
			m.log.Debug("public read", "port", m.port, "err", err)
			continue
		}
		client := m.client.Load()
		if client == nil {
			continue // tunnel not up yet
		}
		protocol.PutDataHeader(buf, m.peer(from).id)
		if _, err := m.tun.WriteToUDPAddrPort(buf[:protocol.DataHeaderLen+n], *client); err != nil {
			m.log.Debug("tunnel write", "port", m.port, "err", err)
		}
	}
}

// peer returns the peer for addr, creating it on first contact.
func (m *mapping) peer(addr netip.AddrPort) *peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.byAddr[addr]
	if p == nil {
		m.nextID++
		p = &peer{id: m.nextID, addr: addr}
		m.peers[p.id] = p
		m.byAddr[addr] = p
		m.log.Debug("new peer", "port", m.port, "peer", addr, "id", p.id)
	}
	p.touch()
	return p
}

// deliver sends a payload from the tunnel to the WAN peer it is addressed to.
func (m *mapping) deliver(id uint32, payload []byte) {
	m.mu.Lock()
	p := m.peers[id]
	m.mu.Unlock()
	if p == nil {
		return // expired
	}
	p.touch()
	if _, err := m.pub.WriteToUDPAddrPort(payload, p.addr); err != nil {
		m.log.Debug("public write", "port", m.port, "peer", p.addr, "err", err)
	}
}

func (m *mapping) expirePeers(ctx context.Context) {
	tick := time.NewTicker(max(m.peerTimeout/4, time.Second))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			cutoff := now.Add(-m.peerTimeout).UnixNano()
			m.mu.Lock()
			for addr, p := range m.byAddr {
				if p.lastSeen.Load() < cutoff {
					delete(m.byAddr, addr)
					delete(m.peers, p.id)
					m.log.Debug("peer expired", "port", m.port, "peer", addr, "id", p.id)
				}
			}
			m.mu.Unlock()
		}
	}
}
