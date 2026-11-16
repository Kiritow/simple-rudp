package client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"simple-rudp/internal/protocol"
)

// session is the client end of a control session. Its requests may travel
// over any connection and through proxies: the server knows the session by
// its ID and checks each request's signature and sequence number.
type session struct {
	c     *Client
	id    protocol.ID
	key   []byte        // request-signing key
	lease time.Duration // how long the server keeps the session without a request

	mu  sync.Mutex // serializes signed requests, so sequence numbers arrive in order
	seq uint64
}

// openSession creates a session and authenticates it: first the server
// proves it knows the secret key, then the client does.
func (c *Client) openSession(ctx context.Context) (*session, error) {
	nonce := protocol.NewNonce()
	var hello protocol.HelloResponse
	err := c.call(ctx, http.MethodPost, protocol.PathSessions, protocol.HelloRequest{Version: protocol.Version, Nonce: nonce}, &hello, nil)
	if err != nil {
		return nil, err
	}
	if len(hello.Nonce) != protocol.NonceLen ||
		!hmac.Equal(hello.Proof, protocol.ServerProof(c.key, nonce, hello.Nonce, hello.Session)) {
		return nil, errors.New("server failed to prove it knows the secret key")
	}
	var auth protocol.AuthResponse
	proof := protocol.ClientProof(c.key, nonce, hello.Nonce, hello.Session)
	if err := c.call(ctx, http.MethodPost, protocol.SessionPath(hello.Session, "auth"), protocol.AuthRequest{Proof: proof}, &auth, nil); err != nil {
		return nil, err
	}
	if auth.Lease() <= 0 {
		return nil, fmt.Errorf("server granted an invalid lease (%d ms)", auth.LeaseMillis)
	}
	return &session{
		c:     c,
		id:    hello.Session,
		key:   protocol.SessionKey(c.key, nonce, hello.Nonce, hello.Session),
		lease: auth.Lease(),
	}, nil
}

// openMapping asks the server to open port for as long as the session lives.
func (s *session) openMapping(ctx context.Context, port int) (protocol.Mapping, error) {
	var m protocol.Mapping
	err := s.c.call(ctx, http.MethodPost, protocol.SessionPath(s.id, "mappings"), protocol.MappingRequest{Port: port}, &m, s)
	return m, err
}

// keepAlive renews the lease three times per lease period until ctx is done
// or the session is lost, and returns why it stopped.
func (s *session) keepAlive(ctx context.Context, log *slog.Logger) error {
	tick := time.NewTicker(s.lease / 3)
	defer tick.Stop()
	renewed := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		err := s.c.call(ctx, http.MethodPost, protocol.SessionPath(s.id, "heartbeat"), nil, nil, s)
		switch {
		case err == nil:
			renewed = time.Now()
		case ctx.Err() != nil:
			return ctx.Err()
		case sessionLost(err):
			return fmt.Errorf("session lost: %w", err)
		case time.Since(renewed) >= s.lease:
			return fmt.Errorf("lease ran out: %w", err)
		default:
			log.Warn("heartbeat failed", "err", err)
		}
	}
}

// close ends the session right away instead of letting its lease run out.
// It is best effort.
func (s *session) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.c.call(ctx, http.MethodDelete, protocol.SessionPath(s.id), nil, nil, s)
}

// StatusError is a non-2xx answer from the server.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Code) }

// sessionLost reports whether err means the server no longer honors the session.
func sessionLost(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusNotFound)
}

// call sends a request with in as its JSON body (if non-nil) to path below
// the API root and decodes a 2xx response into out (if non-nil). With sess,
// the request is signed for that session.
func (c *Client) call(ctx context.Context, method, path string, in, out any, sess *session) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.JoinPath(path).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sess != nil {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		sess.seq++
		sig := protocol.SignRequest(sess.key, method, path, sess.seq, body)
		req.Header.Set(protocol.HeaderSeq, strconv.FormatUint(sess.seq, 10))
		req.Header.Set(protocol.HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e protocol.ErrorResponse
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode) // e.g. a proxy's own error page
		}
		return &StatusError{Code: resp.StatusCode, Message: e.Error}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
