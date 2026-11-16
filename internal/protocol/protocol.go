// Package protocol defines what the rudp server and client say to each other.
//
// # Control API (HTTP or HTTPS)
//
// The control API is plain request/response HTTP. It never relies on the
// underlying TCP connection, so it works through reverse proxies such as
// nginx. State lives in sessions:
//
//	POST   /v1/sessions                {version, nonce} → 201 {session, nonce, proof}
//	POST   /v1/sessions/{id}/auth      {proof}          → 200 {lease_ms}
//	POST   /v1/sessions/{id}/heartbeat                  → 204                         signed
//	POST   /v1/sessions/{id}/mappings  {port}           → 201 {id, port, tunnel_port} signed
//	DELETE /v1/sessions/{id}                            → 204                         signed
//
// A new session is pending. The server's proof shows the client that the
// server knows the secret key; the client's proof in auth makes the session
// active. A pending session can do nothing but authenticate, gets one attempt,
// and is dropped after a deadline (60s by default).
//
// Requests to an active session are signed with a key derived from the secret
// key and both nonces, and carry a sequence number that must increase (see
// [SignRequest]). They can be neither forged nor replayed, even over plain
// HTTP or through a proxy that terminates TLS. Every signed request renews the
// session's lease; when the lease runs out, the session and all its mappings
// are closed. Errors come back as a non-2xx status with body {error}.
//
// # Tunnel (UDP)
//
// For each mapping the client sends tunnel traffic from one UDP socket to the
// server's fixed tunnel port. Every datagram starts with a one-byte type:
//
//	Register  client → server  0x01 | mapping ID (16 bytes)
//	Ack       server → client  0x02
//	Data      both directions  0x03 | peer ID (uint32, big endian) | payload
//
// Register doubles as keepalive: it tells the server which address the
// client's tunnel traffic comes from and keeps NAT mappings along the way
// open. Data packets carry no mapping ID; the server attributes them by
// source address. The peer ID names one WAN peer of the mapping, as assigned
// by the server, so the client can give each peer its own local socket.
//
// Payloads are forwarded as-is: no encryption, no retransmission, no
// ordering. Whatever UDP does, the tunnel does.
package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// Version is the protocol version spoken by this package.
const Version = 1

// RequestTimeout bounds each control request.
const RequestTimeout = 10 * time.Second

// IDLen is the length of an ID in bytes.
const IDLen = 16

// ID identifies a session or a mapping. IDs are random, so a mapping ID also
// serves as the credential for registering a tunnel address.
type ID [IDLen]byte

// NewID returns a random ID.
func NewID() ID {
	var id ID
	rand.Read(id[:]) // never fails since Go 1.24
	return id
}

// ParseID parses the hex form produced by String.
func ParseID(s string) (ID, error) {
	var id ID
	err := id.UnmarshalText([]byte(s))
	return id, err
}

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// Short returns a prefix of the ID for logs.
func (id ID) Short() string { return id.String()[:8] }

// MarshalText implements [encoding.TextMarshaler].
func (id ID) MarshalText() ([]byte, error) { return hex.AppendEncode(nil, id[:]), nil }

// UnmarshalText implements [encoding.TextUnmarshaler].
func (id *ID) UnmarshalText(b []byte) error {
	if hex.DecodedLen(len(b)) != IDLen {
		return errors.New("protocol: id must be 32 hex digits")
	}
	_, err := hex.Decode(id[:], b)
	return err
}
