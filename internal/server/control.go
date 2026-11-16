package server

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"simple-rudp/internal/protocol"
)

const maxBody = 64 << 10

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathSessions, s.handleHello)
	mux.HandleFunc("POST "+protocol.PathSessions+"/{id}/auth", s.handleAuth)
	mux.HandleFunc("POST "+protocol.PathSessions+"/{id}/heartbeat", s.signed(s.handleHeartbeat))
	mux.HandleFunc("POST "+protocol.PathSessions+"/{id}/mappings", s.signed(s.handleOpenMapping))
	mux.HandleFunc("DELETE "+protocol.PathSessions+"/{id}", s.signed(s.handleClose))
	return mux
}

func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	var req protocol.HelloRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Version != protocol.Version {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported protocol version %d (want %d)", req.Version, protocol.Version))
		return
	}
	if len(req.Nonce) != protocol.NonceLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("nonce must be %d bytes", protocol.NonceLen))
		return
	}
	ch := &challenge{client: req.Nonce, server: protocol.NewNonce()}
	sess, err := s.newSession(ch, requestLog(s.log, r))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	sess.log.Debug("session created")
	writeJSON(w, http.StatusCreated, protocol.HelloResponse{
		Session: sess.id,
		Nonce:   ch.server,
		Proof:   protocol.ServerProof(s.key, ch.client, ch.server, sess.id),
	})
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req protocol.AuthRequest
	if !readJSON(w, r, &req) {
		return
	}
	sess, active := s.lookup(id)
	switch {
	case sess == nil:
		writeError(w, http.StatusNotFound, "unknown session")
		return
	case active:
		writeError(w, http.StatusConflict, "session already authenticated")
		return
	}
	ch := sess.takeChallenge()
	if ch == nil {
		writeError(w, http.StatusUnauthorized, "authentication already attempted")
		return
	}
	if !hmac.Equal(req.Proof, protocol.ClientProof(s.key, ch.client, ch.server, id)) {
		sess.log.Warn("authentication failed")
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}
	if !s.activate(sess, protocol.SessionKey(s.key, ch.client, ch.server, id)) {
		writeError(w, http.StatusNotFound, "session expired")
		return
	}
	sess.log.Info("session authenticated")
	writeJSON(w, http.StatusOK, protocol.AuthResponse{LeaseMillis: s.cfg.SessionTimeout.Milliseconds()})
}

// signedHandler handles a verified request to an active session.
type signedHandler func(w http.ResponseWriter, r *http.Request, sess *session, body []byte)

// signed admits only requests to an active session that carry a valid
// signature and a fresh sequence number. Admitted requests renew the lease.
func (s *Server) signed(h signedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			writeError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		seq, err1 := strconv.ParseUint(r.Header.Get(protocol.HeaderSeq), 10, 64)
		sig, err2 := base64.StdEncoding.DecodeString(r.Header.Get(protocol.HeaderSignature))
		if err1 != nil || err2 != nil {
			writeError(w, http.StatusUnauthorized, "missing or malformed request signature")
			return
		}

		sess, active := s.lookup(id)
		switch {
		case sess == nil:
			writeError(w, http.StatusNotFound, "unknown session")
			return
		case !active:
			writeError(w, http.StatusUnauthorized, "session not authenticated")
			return
		}
		if err := sess.verify(r.Method, r.URL.Path, seq, sig, body); err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, errSessionClosed) {
				status = http.StatusNotFound
			} else {
				sess.log.Warn("rejected request", "method", r.Method, "path", r.URL.Path, "err", err)
			}
			writeError(w, status, err.Error())
			return
		}
		h(w, r, sess, body)
	}
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, sess *session, body []byte) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleOpenMapping(w http.ResponseWriter, r *http.Request, sess *session, body []byte) {
	var req protocol.MappingRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	m, status, err := s.openMapping(sess, req.Port)
	if err != nil {
		sess.log.Warn("mapping refused", "port", req.Port, "err", err)
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, protocol.Mapping{ID: m.id, Port: m.port, TunnelPort: s.tunnelPort})
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request, sess *session, body []byte) {
	s.endSession(sess, "closed by client")
	w.WriteHeader(http.StatusNoContent)
}

// requestLog adds the request's origin to log. Behind a proxy RemoteAddr is
// the proxy, so X-Forwarded-For is logged too (informational only).
func requestLog(log *slog.Logger, r *http.Request) *slog.Logger {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	log = log.With("remote", host)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		log = log.With("forwarded_for", xff)
	}
	return log
}

func pathID(w http.ResponseWriter, r *http.Request) (protocol.ID, bool) {
	id, err := protocol.ParseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown session")
		return id, false
	}
	return id, true
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, protocol.ErrorResponse{Error: msg})
}
