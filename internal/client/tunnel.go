package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"simple-rudp/internal/protocol"
)

// tunnel is the client half of one established mapping.
type tunnel struct {
	conn        net.Conn     // UDP socket connected to the server's tunnel port
	mapping     protocol.ID  // goes into Register packets
	local       *net.UDPAddr // where WAN traffic is delivered
	keepalive   time.Duration
	peerTimeout time.Duration
	log         *slog.Logger

	lastAck atomic.Int64 // unix nanoseconds of the last Ack; 0 until the tunnel is up

	mu     sync.Mutex
	closed bool
	peers  map[uint32]*localPeer
	wg     sync.WaitGroup // relayLocal goroutines
}

// localPeer is the local socket standing in for one WAN peer, so the local
// service sees each WAN peer as a distinct source address.
type localPeer struct {
	id       uint32
	conn     *net.UDPConn
	lastSeen atomic.Int64 // unix nanoseconds
}

func (p *localPeer) touch() { p.lastSeen.Store(time.Now().UnixNano()) }

// run relays traffic until ctx is done, control returns (the control session
// is lost), or the server stops answering keepalives, and returns the reason
// it stopped.
func (t *tunnel) run(ctx context.Context, control func(context.Context) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	context.AfterFunc(ctx, func() {
		t.conn.Close()
		t.closePeers()
	})

	var wg sync.WaitGroup
	wg.Go(func() { cancel(control(ctx)) })
	wg.Go(func() { cancel(t.keepAlive(ctx)) })
	wg.Go(func() { t.expirePeers(ctx) })
	wg.Go(t.readTunnel)
	wg.Wait()
	t.wg.Wait()
	return context.Cause(ctx)
}

// keepAlive sends Register packets, every second until the server answers
// and every t.keepalive after that. It fails once the server has been silent
// for three keepalive intervals.
func (t *tunnel) keepAlive(ctx context.Context) error {
	register := protocol.AppendRegister(nil, t.mapping)
	deadAfter := 3 * t.keepalive
	start := time.Now()
	var lastSent time.Time

	tick := time.NewTicker(min(time.Second, t.keepalive))
	defer tick.Stop()
	for {
		now := time.Now()
		lastAck := t.lastAck.Load()
		if lastAck == 0 || now.Sub(lastSent) >= t.keepalive {
			if _, err := t.conn.Write(register); err != nil {
				t.log.Debug("tunnel write", "err", err)
			}
			lastSent = now
		}
		heard := start
		if lastAck != 0 {
			heard = time.Unix(0, lastAck)
		}
		if silent := now.Sub(heard); silent > deadAfter {
			return fmt.Errorf("no answer from tunnel for %s", silent.Round(time.Second))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// readTunnel handles everything the server sends until the socket is closed.
func (t *tunnel) readTunnel() {
	buf := make([]byte, protocol.MaxDatagram)
	for {
		n, err := t.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Usually ECONNREFUSED from an ICMP error; keepAlive notices
			// if the server is really gone.
			t.log.Debug("tunnel read", "err", err)
			continue
		}
		pkt := buf[:n]

		if id, payload, ok := protocol.ParseData(pkt); ok {
			if p := t.peer(id); p != nil {
				p.touch()
				if _, err := p.conn.Write(payload); err != nil {
					t.log.Debug("local write", "peer", id, "err", err)
				}
			}
			continue
		}
		if protocol.IsAck(pkt) && t.lastAck.Swap(time.Now().UnixNano()) == 0 {
			t.log.Info("tunnel up")
		}
	}
}

// peer returns the local socket for WAN peer id, opening it on first use.
// It returns nil once the tunnel is closing.
func (t *tunnel) peer(id uint32) *localPeer {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	if p := t.peers[id]; p != nil {
		return p
	}
	conn, err := net.DialUDP("udp", nil, t.local)
	if err != nil {
		t.log.Warn("dial local service", "err", err)
		return nil
	}
	p := &localPeer{id: id, conn: conn}
	t.peers[id] = p
	t.wg.Go(func() { t.relayLocal(p) })
	t.log.Debug("new peer", "peer", id, "local_src", conn.LocalAddr())
	return p
}

// relayLocal forwards the local service's replies to p into the tunnel until
// p's socket is closed.
func (t *tunnel) relayLocal(p *localPeer) {
	buf := make([]byte, protocol.DataHeaderLen+protocol.MaxDatagram)
	protocol.PutDataHeader(buf, p.id) // the header never changes for this peer
	for {
		n, err := p.conn.Read(buf[protocol.DataHeaderLen:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Usually ECONNREFUSED: the local service isn't listening (yet).
			t.log.Debug("local read", "peer", p.id, "err", err)
			continue
		}
		p.touch()
		if _, err := t.conn.Write(buf[:protocol.DataHeaderLen+n]); err != nil {
			t.log.Debug("tunnel write", "err", err)
		}
	}
}

func (t *tunnel) expirePeers(ctx context.Context) {
	tick := time.NewTicker(max(t.peerTimeout/4, time.Second))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			cutoff := now.Add(-t.peerTimeout).UnixNano()
			t.mu.Lock()
			for id, p := range t.peers {
				if p.lastSeen.Load() < cutoff {
					p.conn.Close()
					delete(t.peers, id)
					t.log.Debug("peer expired", "peer", id)
				}
			}
			t.mu.Unlock()
		}
	}
}

func (t *tunnel) closePeers() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for id, p := range t.peers {
		p.conn.Close()
		delete(t.peers, id)
	}
}
