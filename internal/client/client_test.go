package client

import "testing"

func TestParseMapping(t *testing.T) {
	tests := []struct {
		in   string
		want Mapping
	}{
		{"51820:127.0.0.1:51820", Mapping{51820, "127.0.0.1:51820"}},
		{"5353:[::1]:53", Mapping{5353, "[::1]:53"}},
		{"0:localhost:9000", Mapping{0, "localhost:9000"}},
	}
	for _, tt := range tests {
		got, err := ParseMapping(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseMapping(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
		if got.String() != tt.in {
			t.Errorf("String() = %q; want %q", got.String(), tt.in)
		}
	}
	for _, bad := range []string{"", "51820", "51820:127.0.0.1", "x:127.0.0.1:1", "70000:127.0.0.1:1", "1:::1:53"} {
		if _, err := ParseMapping(bad); err == nil {
			t.Errorf("ParseMapping(%q) succeeded; want error", bad)
		}
	}
}

func TestParseServerURL(t *testing.T) {
	for in, want := range map[string]string{
		"example.com:7000":          "http://example.com:7000",
		"http://example.com:7000":   "http://example.com:7000",
		"https://example.com/rudp/": "https://example.com/rudp/",
		"https://[::1]:7000/a/b":    "https://[::1]:7000/a/b",
	} {
		u, err := ParseServerURL(in)
		if err != nil || u.String() != want {
			t.Errorf("ParseServerURL(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, bad := range []string{"ftp://example.com", "http://", "http://%zz"} {
		if _, err := ParseServerURL(bad); err == nil {
			t.Errorf("ParseServerURL(%q) succeeded; want error", bad)
		}
	}
}
