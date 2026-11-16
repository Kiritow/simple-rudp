package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// NonceLen is the length of hello nonces in bytes.
const NonceLen = 32

const (
	serverProofLabel = "rudp/1 server proof"
	clientProofLabel = "rudp/1 client proof"
	sessionKeyLabel  = "rudp/1 session key"
	requestLabel     = "rudp/1 request"
)

// NewNonce returns NonceLen random bytes.
func NewNonce() []byte {
	b := make([]byte, NonceLen)
	rand.Read(b) // never fails since Go 1.24
	return b
}

// ServerProof is the server's proof, in a HelloResponse, that it knows key.
func ServerProof(key, clientNonce, serverNonce []byte, session ID) []byte {
	return mac(key, serverProofLabel, clientNonce, serverNonce, session[:])
}

// ClientProof is the client's proof, in an AuthRequest, that it knows key.
// It differs from ServerProof only in its label, so neither can stand in for
// the other.
func ClientProof(key, clientNonce, serverNonce []byte, session ID) []byte {
	return mac(key, clientProofLabel, clientNonce, serverNonce, session[:])
}

// SessionKey derives the key that signs requests to an active session. Only
// holders of the secret key can compute it, and every session gets its own.
func SessionKey(key, clientNonce, serverNonce []byte, session ID) []byte {
	return mac(key, sessionKeyLabel, clientNonce, serverNonce, session[:])
}

// SignRequest signs a request to an active session. path is relative to the
// API root (as in [SessionPath]), so the signature survives a reverse proxy
// that mounts the API under a prefix.
func SignRequest(sessionKey []byte, method, path string, seq uint64, body []byte) []byte {
	sum := sha256.Sum256(body)
	return mac(sessionKey, requestLabel, []byte(method), []byte(path), binary.BigEndian.AppendUint64(nil, seq), sum[:])
}

// mac returns HMAC-SHA256 under key of the label and fields, each prefixed
// with its length so that no two inputs encode the same.
func mac(key []byte, label string, fields ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	var n [binary.MaxVarintLen64]byte
	for _, f := range append([][]byte{[]byte(label)}, fields...) {
		m.Write(binary.AppendUvarint(n[:0], uint64(len(f))))
		m.Write(f)
	}
	return m.Sum(nil)
}
