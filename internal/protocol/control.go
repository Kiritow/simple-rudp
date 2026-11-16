package protocol

import (
	"path"
	"time"
)

// PathSessions is the collection of control sessions. Paths are relative to
// the API root; a reverse proxy may mount that root under a prefix.
const PathSessions = "/v1/sessions"

// SessionPath returns the path of session id, or of a resource below it.
func SessionPath(id ID, elem ...string) string {
	return path.Join(append([]string{PathSessions, id.String()}, elem...)...)
}

// Headers of signed requests.
const (
	HeaderSeq       = "Rudp-Seq"       // decimal sequence number
	HeaderSignature = "Rudp-Signature" // base64 of SignRequest
)

// HelloRequest creates a pending session.
type HelloRequest struct {
	Version int    `json:"version"`
	Nonce   []byte `json:"nonce"` // NonceLen random bytes chosen by the client
}

// HelloResponse identifies the new session and proves the server knows the key.
type HelloResponse struct {
	Session ID     `json:"session"`
	Nonce   []byte `json:"nonce"` // NonceLen random bytes chosen by the server
	Proof   []byte `json:"proof"` // ServerProof
}

// AuthRequest proves the client knows the key, activating the session.
type AuthRequest struct {
	Proof []byte `json:"proof"` // ClientProof
}

// AuthResponse tells the client how often it must renew the session.
type AuthResponse struct {
	LeaseMillis int64 `json:"lease_ms"`
}

// Lease returns how long the server keeps the session without a signed request.
func (r AuthResponse) Lease() time.Duration { return time.Duration(r.LeaseMillis) * time.Millisecond }

// MappingRequest asks the server to open a public port.
type MappingRequest struct {
	Port int `json:"port"` // 0 lets the server pick
}

// Mapping describes an opened public port.
type Mapping struct {
	ID         ID  `json:"id"`          // goes into Register packets
	Port       int `json:"port"`        // public port actually opened
	TunnelPort int `json:"tunnel_port"` // where to send tunnel traffic
}

// ErrorResponse is the body of every non-2xx response.
type ErrorResponse struct {
	Error string `json:"error"`
}
