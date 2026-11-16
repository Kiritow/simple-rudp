package server

import (
	"context"
	"crypto/hmac"
	"errors"
	"log/slog"
	"sync"
	"time"

	"simple-rudp/internal/protocol"
)

// maxPending caps unauthenticated sessions, so hello floods can't exhaust memory.
const maxPending = 1024

var (
	errSessionClosed = errors.New("session closed")
	errBadSignature  = errors.New("bad request signature")
	errReplay        = errors.New("request sequence number not increasing")
)

// session is a control session. It starts pending and becomes active when
// the client proves it knows the secret key. Mappings belong to the session
// that opened them and close with it.
type session struct {
	id      protocol.ID
	created time.Time
	log     *slog.Logger

	mu        sync.Mutex
	challenge *challenge // until the client's single auth attempt
	key       []byte     // request-signing key; nil while pending
	lastSeq   uint64
	renewed   time.Time // when the last valid signed request arrived
	closed    bool
	mappings  []*mapping
}

type challenge struct{ client, server []byte }

// takeChallenge returns the hello nonces once; later calls return nil, so
// each session allows a single auth attempt.
func (sess *session) takeChallenge() *challenge {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	ch := sess.challenge
	sess.challenge = nil
	return ch
}

// verify checks a signed request. If it is valid, it records seq and renews
// the lease.
func (sess *session) verify(method, path string, seq uint64, sig, body []byte) error {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closed {
		return errSessionClosed
	}
	if !hmac.Equal(sig, protocol.SignRequest(sess.key, method, path, seq, body)) {
		return errBadSignature
	}
	if seq <= sess.lastSeq {
		return errReplay
	}
	sess.lastSeq = seq
	sess.renewed = time.Now()
	return nil
}

func (sess *session) idleSince(now time.Time) time.Duration {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return now.Sub(sess.renewed)
}

// addMapping makes m part of the session. It fails if the session is closed.
func (sess *session) addMapping(m *mapping) bool {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closed {
		return false
	}
	sess.mappings = append(sess.mappings, m)
	return true
}

// close ends the session and all its mappings.
func (sess *session) close(reason string) {
	sess.mu.Lock()
	if sess.closed {
		sess.mu.Unlock()
		return
	}
	sess.closed = true
	wasActive := sess.key != nil
	ms := sess.mappings
	sess.mappings = nil
	sess.mu.Unlock()

	for _, m := range ms {
		m.cancel()
	}
	if wasActive {
		sess.log.Info("session closed", "reason", reason)
	} else {
		sess.log.Debug("pending session dropped", "reason", reason)
	}
}

// newSession registers a pending session, unless too many are pending.
func (s *Server) newSession(ch *challenge, log *slog.Logger) (*session, error) {
	id := protocol.NewID()
	sess := &session{id: id, created: time.Now(), challenge: ch, log: log.With("session", id.Short())}
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	switch {
	case s.closing:
		return nil, errors.New("server shutting down")
	case len(s.pending) >= maxPending:
		return nil, errors.New("too many pending sessions")
	}
	s.pending[id] = sess
	return sess, nil
}

// lookup returns the session with id and whether it is active.
func (s *Server) lookup(id protocol.ID) (sess *session, active bool) {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	if sess := s.active[id]; sess != nil {
		return sess, true
	}
	return s.pending[id], false
}

// activate moves a pending session to active. It fails if the session was
// dropped in the meantime.
func (s *Server) activate(sess *session, key []byte) bool {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	if s.pending[sess.id] != sess {
		return false
	}
	delete(s.pending, sess.id)
	sess.mu.Lock()
	sess.key = key
	sess.renewed = time.Now()
	sess.mu.Unlock()
	s.active[sess.id] = sess
	return true
}

// endSession removes sess and closes it.
func (s *Server) endSession(sess *session, reason string) {
	s.ctlMu.Lock()
	if s.active[sess.id] == sess {
		delete(s.active, sess.id)
	}
	if s.pending[sess.id] == sess {
		delete(s.pending, sess.id)
	}
	s.ctlMu.Unlock()
	sess.close(reason)
}

// expireSessions drops pending sessions past the auth deadline and active
// sessions whose lease ran out, until ctx is done.
func (s *Server) expireSessions(ctx context.Context) {
	tick := time.NewTicker(min(time.Second, max(min(s.cfg.AuthTimeout, s.cfg.SessionTimeout)/4, 10*time.Millisecond)))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			var unauthed, idle []*session
			s.ctlMu.Lock()
			for id, sess := range s.pending {
				if now.Sub(sess.created) >= s.cfg.AuthTimeout {
					delete(s.pending, id)
					unauthed = append(unauthed, sess)
				}
			}
			for id, sess := range s.active {
				if sess.idleSince(now) >= s.cfg.SessionTimeout {
					delete(s.active, id)
					idle = append(idle, sess)
				}
			}
			s.ctlMu.Unlock()
			for _, sess := range unauthed {
				sess.close("not authenticated in time")
			}
			for _, sess := range idle {
				sess.close("lease expired")
			}
		}
	}
}

// closeAllSessions ends every session and refuses new ones.
func (s *Server) closeAllSessions() {
	s.ctlMu.Lock()
	s.closing = true
	all := make([]*session, 0, len(s.pending)+len(s.active))
	for _, sess := range s.pending {
		all = append(all, sess)
	}
	for _, sess := range s.active {
		all = append(all, sess)
	}
	clear(s.pending)
	clear(s.active)
	s.ctlMu.Unlock()
	for _, sess := range all {
		sess.close("server shutting down")
	}
}
