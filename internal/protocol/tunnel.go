package protocol

import "encoding/binary"

// Tunnel packet types.
const (
	TypeRegister byte = 0x01
	TypeAck      byte = 0x02
	TypeData     byte = 0x03
)

// DataHeaderLen is the size of the header preceding the payload of a Data
// packet. Reserve this many bytes in front of a read buffer to build a Data
// packet without copying.
const DataHeaderLen = 5

// MaxDatagram is large enough to hold any UDP datagram.
const MaxDatagram = 64 << 10

// AppendRegister appends a Register packet for mapping id to b.
func AppendRegister(b []byte, id ID) []byte {
	return append(append(b, TypeRegister), id[:]...)
}

// ParseRegister reports whether b is a Register packet and returns its mapping ID.
func ParseRegister(b []byte) (ID, bool) {
	var id ID
	if len(b) != 1+IDLen || b[0] != TypeRegister {
		return id, false
	}
	copy(id[:], b[1:])
	return id, true
}

// AppendAck appends an Ack packet to b.
func AppendAck(b []byte) []byte { return append(b, TypeAck) }

// IsAck reports whether b is an Ack packet.
func IsAck(b []byte) bool { return len(b) == 1 && b[0] == TypeAck }

// PutDataHeader writes a Data header for peer into b[:DataHeaderLen].
func PutDataHeader(b []byte, peer uint32) {
	_ = b[DataHeaderLen-1] // bounds check hint
	b[0] = TypeData
	binary.BigEndian.PutUint32(b[1:DataHeaderLen], peer)
}

// ParseData reports whether b is a Data packet and splits it into peer ID and
// payload. The payload aliases b.
func ParseData(b []byte) (peer uint32, payload []byte, ok bool) {
	if len(b) < DataHeaderLen || b[0] != TypeData {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(b[1:DataHeaderLen]), b[DataHeaderLen:], true
}
