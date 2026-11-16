// Package e2e_test runs real servers, clients and local services on loopback.
package e2e_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"simple-rudp/internal/client"
	"simple-rudp/internal/protocol"
	"simple-rudp/internal/server"
)

const secret = "s3cret"

var (
	loopback = net.IPv4(127, 0, 0, 1)
	discard  = slog.New(slog.DiscardHandler)
)

func TestForwarding(t *testing.T) {
	tests := []struct {
		name  string
		tls   bool
		proxy bool
	}{
		{name: "http"},
		{name: "https", tls: true},
		{name: "behind reverse proxy", proxy: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
			cfg := server.Config{SecretKey: secret, BindHost: "127.0.0.1", Logger: log.With("side", "server")}
			if tt.tls {
				cfg.TLS = selfSigned(t)
			}
			serverURL := startServer(t, cfg)
			if tt.proxy {
				serverURL = startReverseProxy(t, serverURL, "/rudp")
			}
			echo := startEcho(t)
			publicPort := freeUDPPort(t)
			stopClient := startClient(t, client.Config{
				ServerURL: serverURL,
				SecretKey: secret,
				Insecure:  tt.tls,
				Mappings:  []client.Mapping{{RemotePort: publicPort, LocalAddr: echo}},
				Keepalive: 500 * time.Millisecond,
				Logger:    log.With("side", "client"),
			})

			public := net.JoinHostPort("127.0.0.1", strconv.Itoa(publicPort))
			a, b := dialUDP(t, public), dialUDP(t, public)
			srcA := roundTrip(t, a, "hello from a")
			srcB := roundTrip(t, b, "hello from b")
			if srcA == srcB {
				t.Errorf("WAN peers a and b reached the service from the same address %s; want one socket each", srcA)
			}
			if got := roundTrip(t, a, "again from a"); got != srcA {
				t.Errorf("peer a's second packet came from %s; want %s as before", got, srcA)
			}
			big := strings.Repeat("x", 8000) // larger than any MTU: fragmentation is fine for plain UDP
			if got := roundTrip(t, b, big); got != srcB {
				t.Errorf("peer b's large packet came from %s; want %s", got, srcB)
			}

			// A stopping client ends its session, which releases the port at once.
			stopClient()
			waitPortFree(t, publicPort)
		})
	}
}

func TestControlAPI(t *testing.T) {
	okPort := freeUDPPort(t)
	var allow server.PortRanges
	if err := allow.Set(strconv.Itoa(okPort)); err != nil {
		t.Fatal(err)
	}
	api := newAPI(t, startServer(t, server.Config{SecretKey: secret, BindHost: "127.0.0.1", AllowPorts: allow, Logger: discard}))
	open := protocol.MappingRequest{Port: okPort}

	t.Run("unknown session", func(t *testing.T) {
		s := &apiSession{api: api, id: protocol.NewID(), key: []byte("whatever")}
		s.expect(http.MethodPost, "heartbeat", nil, http.StatusNotFound)
	})
	t.Run("bad hello", func(t *testing.T) {
		api.expect(http.MethodPost, protocol.PathSessions, protocol.HelloRequest{Version: 0, Nonce: protocol.NewNonce()}, http.StatusBadRequest)
		api.expect(http.MethodPost, protocol.PathSessions, protocol.HelloRequest{Version: protocol.Version, Nonce: []byte("short")}, http.StatusBadRequest)
	})
	t.Run("pending session can't act", func(t *testing.T) {
		// Even signed with the right session key, nothing works before auth.
		h := api.hello()
		s := &apiSession{api: api, id: h.resp.Session, key: protocol.SessionKey([]byte(secret), h.nonce, h.resp.Nonce, h.resp.Session)}
		s.expect(http.MethodPost, "mappings", open, http.StatusUnauthorized)
		s.expect(http.MethodPost, "heartbeat", nil, http.StatusUnauthorized)
	})
	t.Run("wrong key", func(t *testing.T) {
		h := api.hello()
		if h.serverProofOK("guess") {
			t.Error("server proof verified under the wrong key")
		}
		s, status := api.auth(h, "guess")
		if status != http.StatusUnauthorized {
			t.Fatalf("auth = %d; want %d", status, http.StatusUnauthorized)
		}
		s.expect(http.MethodPost, "mappings", open, http.StatusUnauthorized)
		// One attempt per session: the right key doesn't help any more.
		if _, status := api.auth(h, secret); status != http.StatusUnauthorized {
			t.Errorf("second auth attempt = %d; want %d", status, http.StatusUnauthorized)
		}
	})
	t.Run("active session", func(t *testing.T) {
		h := api.hello()
		if !h.serverProofOK(secret) {
			t.Fatal("server proof did not verify")
		}
		s, status := api.auth(h, secret)
		if status != http.StatusOK {
			t.Fatalf("auth = %d; want %d", status, http.StatusOK)
		}
		if _, status := api.auth(h, secret); status != http.StatusConflict {
			t.Errorf("auth again = %d; want %d", status, http.StatusConflict)
		}

		s.expect(http.MethodPost, "heartbeat", nil, http.StatusNoContent)
		s.seq-- // replay the same sequence number
		s.expect(http.MethodPost, "heartbeat", nil, http.StatusUnauthorized)
		api.expect(http.MethodPost, protocol.SessionPath(s.id, "heartbeat"), nil, http.StatusUnauthorized) // unsigned
		if status := s.send(http.MethodPost, "mappings", open, &protocol.MappingRequest{Port: okPort + 1}, nil); status != http.StatusUnauthorized {
			t.Errorf("tampered body = %d; want %d", status, http.StatusUnauthorized)
		}
		forged := &apiSession{api: api, id: s.id, key: []byte("guessed key"), seq: 100}
		forged.expect(http.MethodPost, "heartbeat", nil, http.StatusUnauthorized)

		s.expect(http.MethodPost, "mappings", protocol.MappingRequest{Port: okPort + 1}, http.StatusForbidden)
		var m protocol.Mapping
		if status := s.send(http.MethodPost, "mappings", open, nil, &m); status != http.StatusCreated {
			t.Fatalf("open mapping = %d; want %d", status, http.StatusCreated)
		}
		if m.Port != okPort || m.TunnelPort == 0 || m.ID == (protocol.ID{}) {
			t.Errorf("mapping = %+v; want port %d with an ID and tunnel port", m, okPort)
		}
		s.expect(http.MethodPost, "mappings", open, http.StatusConflict) // already open

		// Closing the session closes its mappings.
		s.expect(http.MethodDelete, "", nil, http.StatusNoContent)
		waitPortFree(t, okPort)
		s.expect(http.MethodPost, "heartbeat", nil, http.StatusNotFound)
	})
}

func TestDeadlines(t *testing.T) {
	const timeout = 500 * time.Millisecond
	okPort := freeUDPPort(t)
	api := newAPI(t, startServer(t, server.Config{
		SecretKey:      secret,
		BindHost:       "127.0.0.1",
		AuthTimeout:    timeout,
		SessionTimeout: timeout,
		Logger:         discard,
	}))

	start := time.Now()
	pending := api.hello()
	failed, _ := api.auth(api.hello(), "guess")
	active, status := api.auth(api.hello(), secret)
	if status != http.StatusOK {
		t.Fatalf("auth = %d; want %d", status, http.StatusOK)
	}
	active.expect(http.MethodPost, "mappings", protocol.MappingRequest{Port: okPort}, http.StatusCreated)
	// A failed session lingers until the deadline, unable to do anything.
	failed.expect(http.MethodPost, "heartbeat", nil, http.StatusUnauthorized)

	// Heartbeats keep the active session going well past both deadlines.
	for time.Since(start) < 3*timeout {
		active.expect(http.MethodPost, "heartbeat", nil, http.StatusNoContent)
		time.Sleep(timeout / 5)
	}

	// Unauthenticated sessions are gone: completing the handshake now fails.
	if _, status := api.auth(pending, secret); status != http.StatusNotFound {
		t.Errorf("auth after the deadline = %d; want %d", status, http.StatusNotFound)
	}
	failed.expect(http.MethodPost, "heartbeat", nil, http.StatusNotFound)

	// Without heartbeats the lease runs out and the port is released.
	waitPortFree(t, okPort)
	active.expect(http.MethodPost, "heartbeat", nil, http.StatusNotFound)
}

func TestClientRejectsWrongKey(t *testing.T) {
	var logs syncBuffer
	startClient(t, client.Config{
		ServerURL: startServer(t, server.Config{SecretKey: secret, Logger: discard}),
		SecretKey: "guess",
		Mappings:  []client.Mapping{{RemotePort: freeUDPPort(t), LocalAddr: "127.0.0.1:9"}},
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	logs.waitFor(t, "server failed to prove it knows the secret key")
}

func TestClientVerifiesCertificates(t *testing.T) {
	var logs syncBuffer
	startClient(t, client.Config{
		ServerURL: startServer(t, server.Config{SecretKey: secret, TLS: selfSigned(t), Logger: discard}),
		SecretKey: secret,
		Mappings:  []client.Mapping{{RemotePort: freeUDPPort(t), LocalAddr: "127.0.0.1:9"}},
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	logs.waitFor(t, "tls: failed to verify certificate")
}

// api speaks the control API by hand.
type api struct {
	t    *testing.T
	base string
	hc   *http.Client
}

func newAPI(t *testing.T, base string) *api {
	return &api{t: t, base: base, hc: &http.Client{Timeout: 5 * time.Second}}
}

// do sends a request with body and headers and decodes a 2xx answer into out.
func (a *api) do(method, path string, body []byte, hdr http.Header, out any) int {
	a.t.Helper()
	req, err := http.NewRequest(method, a.base+path, bytes.NewReader(body))
	if err != nil {
		a.t.Fatal(err)
	}
	maps.Copy(req.Header, hdr)
	resp, err := a.hc.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		a.t.Fatal(err)
	}
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(data, out); err != nil {
			a.t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

func (a *api) expect(method, path string, in any, want int) {
	a.t.Helper()
	if got := a.do(method, path, mustJSON(a.t, in), nil, nil); got != want {
		a.t.Errorf("%s %s = %d; want %d", method, path, got, want)
	}
}

type hello struct {
	nonce []byte
	resp  protocol.HelloResponse
}

func (h hello) serverProofOK(key string) bool {
	return hmac.Equal(h.resp.Proof, protocol.ServerProof([]byte(key), h.nonce, h.resp.Nonce, h.resp.Session))
}

func (a *api) hello() hello {
	a.t.Helper()
	h := hello{nonce: protocol.NewNonce()}
	body := mustJSON(a.t, protocol.HelloRequest{Version: protocol.Version, Nonce: h.nonce})
	if got := a.do(http.MethodPost, protocol.PathSessions, body, nil, &h.resp); got != http.StatusCreated {
		a.t.Fatalf("hello = %d; want %d", got, http.StatusCreated)
	}
	return h
}

// auth completes h with key, returning the session it would sign for and the auth status.
func (a *api) auth(h hello, key string) (*apiSession, int) {
	a.t.Helper()
	proof := protocol.ClientProof([]byte(key), h.nonce, h.resp.Nonce, h.resp.Session)
	status := a.do(http.MethodPost, protocol.SessionPath(h.resp.Session, "auth"), mustJSON(a.t, protocol.AuthRequest{Proof: proof}), nil, nil)
	return &apiSession{api: a, id: h.resp.Session, key: protocol.SessionKey([]byte(key), h.nonce, h.resp.Nonce, h.resp.Session)}, status
}

// apiSession signs requests for one session.
type apiSession struct {
	api *api
	id  protocol.ID
	key []byte
	seq uint64
}

// send signs in but sends actual (if non-nil) as the body, to test tampering.
func (s *apiSession) send(method, elem string, in, actual, out any) int {
	s.api.t.Helper()
	path := protocol.SessionPath(s.id)
	if elem != "" {
		path = protocol.SessionPath(s.id, elem)
	}
	body := mustJSON(s.api.t, in)
	s.seq++
	hdr := http.Header{}
	hdr.Set(protocol.HeaderSeq, strconv.FormatUint(s.seq, 10))
	hdr.Set(protocol.HeaderSignature, base64.StdEncoding.EncodeToString(protocol.SignRequest(s.key, method, path, s.seq, body)))
	if actual != nil {
		body = mustJSON(s.api.t, actual)
	}
	return s.api.do(method, path, body, hdr, out)
}

func (s *apiSession) expect(method, elem string, in any, want int) {
	s.api.t.Helper()
	if got := s.send(method, elem, in, nil, nil); got != want {
		s.api.t.Errorf("%s %s = %d; want %d", method, elem, got, want)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// startServer runs a server on loopback ports until the test ends and returns
// its control API URL.
func startServer(t *testing.T, cfg server.Config) string {
	t.Helper()
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tun, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln, tun) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("server: %v", err)
		}
	})
	scheme := "http"
	if cfg.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + ln.Addr().String()
}

// startReverseProxy stands in for nginx: it serves target under prefix,
// strips the prefix, and opens a new upstream connection for every request,
// so nothing can depend on a TCP connection lasting across requests.
func startReverseProxy(t *testing.T, target, prefix string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = &http.Transport{DisableKeepAlives: true}
	ts := httptest.NewServer(http.StripPrefix(prefix, rp))
	t.Cleanup(ts.Close)
	return ts.URL + prefix
}

// startClient runs a client until stop is called or the test ends.
func startClient(t *testing.T, cfg client.Config) (stop func()) {
	t.Helper()
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	stop = sync.OnceFunc(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("client: %v", err)
		}
	})
	t.Cleanup(stop)
	return stop
}

func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	cfg, err := server.SelfSignedTLS()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// startEcho runs a UDP service that answers each datagram with
// "<sender address>|<datagram>", so tests can tell which socket sent it.
func startEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, protocol.MaxDatagram)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			conn.WriteToUDPAddrPort(fmt.Appendf(nil, "%s|%s", from, buf[:n]), from)
		}
	}()
	return conn.LocalAddr().String()
}

func dialUDP(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// roundTrip sends msg until its echo comes back (the tunnel may still be
// coming up) and returns the source address the local service saw.
func roundTrip(t *testing.T, conn *net.UDPConn, msg string) string {
	t.Helper()
	buf := make([]byte, protocol.MaxDatagram)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					time.Sleep(50 * time.Millisecond) // e.g. port not open yet
				}
				break
			}
			// Skip echoes of earlier retries.
			if src, got, ok := strings.Cut(string(buf[:n]), "|"); ok && got == msg {
				return src
			}
		}
	}
	t.Fatalf("no echo for %.20q after 5s", msg)
	return ""
}

// waitPortFree fails the test unless port can be bound again soon.
func waitPortFree(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback, Port: port})
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("public port %d still busy: %v", port, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// syncBuffer collects log output from other goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) waitFor(t *testing.T, substr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(b.String(), substr) {
		if time.Now().After(deadline) {
			t.Fatalf("log never mentioned %q; got:\n%s", substr, b.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
