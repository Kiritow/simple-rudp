package protocol

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"testing"
)

func TestRegisterRoundTrip(t *testing.T) {
	id := NewID()
	got, ok := ParseRegister(AppendRegister(nil, id))
	if !ok || got != id {
		t.Fatalf("ParseRegister = %v, %v; want %v, true", got, ok, id)
	}
	for _, bad := range [][]byte{nil, {TypeRegister}, {TypeData, 1, 2, 3, 4}, AppendRegister(nil, id)[1:]} {
		if _, ok := ParseRegister(bad); ok {
			t.Errorf("ParseRegister(%x) ok; want not a Register", bad)
		}
	}
}

func TestDataRoundTrip(t *testing.T) {
	pkt := make([]byte, DataHeaderLen, DataHeaderLen+5)
	PutDataHeader(pkt, 0xdeadbeef)
	pkt = append(pkt, "hello"...)

	peer, payload, ok := ParseData(pkt)
	if !ok || peer != 0xdeadbeef || !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("ParseData = %x, %q, %v; want deadbeef, \"hello\", true", peer, payload, ok)
	}
	if _, payload, ok := ParseData(pkt[:DataHeaderLen]); !ok || len(payload) != 0 {
		t.Errorf("empty payload: ok=%v len=%d; want ok, 0", ok, len(payload))
	}
	if _, _, ok := ParseData(pkt[:DataHeaderLen-1]); ok {
		t.Error("truncated header parsed as Data")
	}
	if _, _, ok := ParseData(AppendAck(nil)); ok {
		t.Error("Ack parsed as Data")
	}
}

func TestID(t *testing.T) {
	id := NewID()
	got, err := ParseID(id.String())
	if err != nil || got != id {
		t.Fatalf("ParseID(String()) = %v, %v; want %v", got, err, id)
	}
	if _, err := ParseID("abcd"); err == nil {
		t.Error("short id accepted")
	}
	if _, err := ParseID(id.String()[:30] + "zz"); err == nil {
		t.Error("non-hex id accepted")
	}

	in := Mapping{ID: id, Port: 51820, TunnelPort: 7001}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Mapping
	if err := json.Unmarshal(b, &out); err != nil || out != in {
		t.Fatalf("JSON round trip = %+v, %v; want %+v", out, err, in)
	}
	if want := "/v1/sessions/" + id.String() + "/auth"; SessionPath(id, "auth") != want {
		t.Errorf("SessionPath = %q; want %q", SessionPath(id, "auth"), want)
	}
}

func TestProofs(t *testing.T) {
	key, cn, sn, sid := []byte("secret"), NewNonce(), NewNonce(), NewID()
	sp := ServerProof(key, cn, sn, sid)

	if !hmac.Equal(sp, ServerProof(key, cn, sn, sid)) {
		t.Fatal("ServerProof is not deterministic")
	}
	for name, other := range map[string][]byte{
		"client role":    ClientProof(key, cn, sn, sid),
		"session key":    SessionKey(key, cn, sn, sid),
		"other key":      ServerProof([]byte("secreT"), cn, sn, sid),
		"swapped nonces": ServerProof(key, sn, cn, sid),
		"other session":  ServerProof(key, cn, sn, NewID()),
	} {
		if hmac.Equal(sp, other) {
			t.Errorf("proof unchanged with %s", name)
		}
	}
}

func TestSignRequest(t *testing.T) {
	key := SessionKey([]byte("secret"), NewNonce(), NewNonce(), NewID())
	path := SessionPath(NewID(), "mappings")
	sig := SignRequest(key, "POST", path, 7, []byte(`{"port":1}`))

	for name, other := range map[string][]byte{
		"other key":    SignRequest(SessionKey([]byte("secret"), NewNonce(), NewNonce(), NewID()), "POST", path, 7, []byte(`{"port":1}`)),
		"other method": SignRequest(key, "DELETE", path, 7, []byte(`{"port":1}`)),
		"other path":   SignRequest(key, "POST", path+"x", 7, []byte(`{"port":1}`)),
		"other seq":    SignRequest(key, "POST", path, 8, []byte(`{"port":1}`)),
		"other body":   SignRequest(key, "POST", path, 7, []byte(`{"port":2}`)),
		// Moving bytes between fields must change the signature.
		"shifted boundary": SignRequest(key, "POS", "T"+path, 7, []byte(`{"port":1}`)),
	} {
		if hmac.Equal(sig, other) {
			t.Errorf("signature unchanged with %s", name)
		}
	}
}
