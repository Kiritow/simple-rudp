package server

import "testing"

func TestPortRanges(t *testing.T) {
	var r PortRanges
	if err := r.Set("10000-10010, 51820"); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("53"); err != nil {
		t.Fatal(err)
	}
	if got, want := r.String(), "10000-10010,51820,53"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
	for port, want := range map[int]bool{
		0: false, 53: true, 9999: false, 10000: true, 10010: true, 10011: false, 51820: true, 70000: false,
	} {
		if got := r.Allows(port); got != want {
			t.Errorf("Allows(%d) = %v; want %v", port, got, want)
		}
	}

	var empty PortRanges
	if !empty.Allows(0) || !empty.Allows(65535) || empty.Allows(65536) {
		t.Error("empty set should allow exactly 0-65535")
	}

	for _, bad := range []string{"0", "65536", "x", "20-10", "1-", "-5"} {
		var r PortRanges
		if err := r.Set(bad); err == nil {
			t.Errorf("Set(%q) succeeded; want error", bad)
		}
	}
}
