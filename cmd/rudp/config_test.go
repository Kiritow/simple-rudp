package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"simple-rudp/internal/server"
)

func TestServerConfig(t *testing.T) {
	file := writeConfig(t, `
control: "127.0.0.1:8000"
tunnel: ":8001"
secret: from-file
allow_ports: [10000-10010, 51820]
session_timeout: 45s
`, 0o600)
	fromFile := serverConfig{
		Control:        "127.0.0.1:8000",
		Tunnel:         ":8001",
		Secret:         "from-file",
		AllowPorts:     ports("10000-10010,51820"),
		SessionTimeout: 45 * time.Second,
		PeerTimeout:    2 * time.Minute, // default
	}
	with := func(f func(*serverConfig)) serverConfig {
		c := fromFile
		c.AllowPorts = append(portRanges(nil), fromFile.AllowPorts...)
		f(&c)
		return c
	}

	tests := []struct {
		name string
		args []string
		env  string // $RUDP_SECRET
		want serverConfig
	}{
		{"defaults", nil, "", defaultServerConfig()},
		{"flags only", []string{"-control", ":1", "-allow-ports", "53"}, "",
			func() serverConfig {
				c := defaultServerConfig()
				c.Control, c.AllowPorts = ":1", ports("53")
				return c
			}()},
		{"file", []string{"-config", file}, "", fromFile},
		{"flags override file", []string{"-config", file, "-tunnel", ":9001", "-v"}, "",
			with(func(c *serverConfig) { c.Tunnel, c.Verbose = ":9001", true })},
		{"flag order doesn't matter", []string{"-tunnel", ":9001", "-config", file}, "",
			with(func(c *serverConfig) { c.Tunnel = ":9001" })},
		{"list flag replaces file list", []string{"-config", file, "-allow-ports", "53", "-allow-ports", "80-81"}, "",
			with(func(c *serverConfig) { c.AllowPorts = ports("53,80-81") })},
		{"env overrides file secret", []string{"-config", file}, "from-env",
			with(func(c *serverConfig) { c.Secret = "from-env" })},
		{"flag overrides env secret", []string{"-config", file, "-secret", "from-flag"}, "from-env",
			with(func(c *serverConfig) { c.Secret = "from-flag" })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("RUDP_SECRET", tt.env)
			c := defaultServerConfig()
			var stderr bytes.Buffer
			if err := parseArgs("rudp server", tt.args, &c, &c.Secret, defineServerFlags, &stderr); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c, tt.want) {
				t.Errorf("got  %+v\nwant %+v", c, tt.want)
			}
			if stderr.Len() > 0 {
				t.Errorf("unexpected output: %s", stderr.String())
			}
		})
	}
}

func TestClientConfig(t *testing.T) {
	t.Setenv("RUDP_SECRET", "")
	file := writeConfig(t, `
server: https://example.com/rudp
insecure: true
mappings:
  - "51820:127.0.0.1:51820"
  - remote_port: 0
    local: "[::1]:53"
keepalive: 5s
`, 0o600)

	c := defaultClientConfig()
	if err := parseArgs("rudp client", []string{"-config", file}, &c, &c.Secret, defineClientFlags, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	want := clientConfig{
		Server:      "https://example.com/rudp",
		Insecure:    true,
		Mappings:    []mapping{{RemotePort: 51820, LocalAddr: "127.0.0.1:51820"}, {RemotePort: 0, LocalAddr: "[::1]:53"}},
		Keepalive:   5 * time.Second,
		PeerTimeout: 2 * time.Minute,
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got  %+v\nwant %+v", c, want)
	}

	c = defaultClientConfig()
	if err := parseArgs("rudp client", []string{"-config", file, "-map", "1:127.0.0.1:2"}, &c, &c.Secret, defineClientFlags, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	if want := []mapping{{RemotePort: 1, LocalAddr: "127.0.0.1:2"}}; !reflect.DeepEqual(c.Mappings, want) {
		t.Errorf("-map with a config file: mappings = %+v; want only %+v", c.Mappings, want)
	}
}

func TestAllowPortsAsString(t *testing.T) {
	file := writeConfig(t, `allow_ports: "10000-10010,51820"`, 0o600)
	c := defaultServerConfig()
	if err := parseArgs("rudp server", []string{"-config", file}, &c, &c.Secret, defineServerFlags, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	if want := ports("10000-10010,51820"); !reflect.DeepEqual(c.AllowPorts, want) {
		t.Errorf("allow_ports = %v; want %v", c.AllowPorts, want)
	}
	if !server.PortRanges(c.AllowPorts).Allows(10005) {
		t.Error("converted ranges don't allow 10005")
	}
}

func TestConfigErrors(t *testing.T) {
	tests := []struct {
		name, yaml string
		args       []string
		want       string // in the error
	}{
		{"unknown key", "contol: :7000", nil, "field contol not found"},
		{"bad port range", "allow_ports: [20-10]", nil, "line 1: invalid port range"},
		{"bad mapping", "mappings:\n  - 51820:127.0.0.1", nil, "line 2: invalid mapping"},
		{"incomplete mapping", "mappings:\n  - local: 127.0.0.1:1", nil, "line 2: a mapping needs remote_port and local"},
		{"duration without unit", "keepalive: 10", nil, "time.Duration"},
		{"missing file", "", []string{"-config", "/nonexistent/rudp.yaml"}, "no such file"},
		{"stray argument", "", []string{"server.yaml"}, `unexpected argument "server.yaml"`},
		{"bad flag", "", []string{"-keepalive", "soon"}, "invalid value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if tt.yaml != "" {
				args = []string{"-config", writeConfig(t, tt.yaml, 0o600)}
			}
			// The client config has every kind of field these cases need,
			// except allow_ports, which only the server has.
			var err error
			if strings.HasPrefix(tt.yaml, "allow_ports") || strings.HasPrefix(tt.yaml, "contol") {
				c := defaultServerConfig()
				err = parseArgs("rudp server", args, &c, &c.Secret, defineServerFlags, new(bytes.Buffer))
			} else {
				c := defaultClientConfig()
				err = parseArgs("rudp client", args, &c, &c.Secret, defineClientFlags, new(bytes.Buffer))
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v; want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestWarnsAboutSharedSecretFile(t *testing.T) {
	for _, tt := range []struct {
		name string
		perm os.FileMode
		env  string
		warn bool
	}{
		{"private file", 0o600, "", false},
		{"world-readable file", 0o644, "", true},
		{"secret from env instead", 0o644, "from-env", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("RUDP_SECRET", tt.env)
			file := writeConfig(t, "secret: s3cret", tt.perm)
			c := defaultServerConfig()
			var stderr bytes.Buffer
			if err := parseArgs("rudp server", []string{"-config", file}, &c, &c.Secret, defineServerFlags, &stderr); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(stderr.String(), "other users can access it"); got != tt.warn {
				t.Errorf("warned = %v; want %v (output %q)", got, tt.warn, stderr.String())
			}
		})
	}
}

func TestExamples(t *testing.T) {
	t.Setenv("RUDP_SECRET", "")
	s := defaultServerConfig()
	if err := parseArgs("rudp server", []string{"-config", "../../examples/server.yaml"}, &s, &s.Secret, defineServerFlags, new(bytes.Buffer)); err != nil {
		t.Fatalf("server example: %v", err)
	}
	c := defaultClientConfig()
	if err := parseArgs("rudp client", []string{"-config", "../../examples/client.yaml"}, &c, &c.Secret, defineClientFlags, new(bytes.Buffer)); err != nil {
		t.Fatalf("client example: %v", err)
	}
	if s.Secret != "" || c.Secret != "" {
		t.Error("examples must not ship a usable secret key")
	}
	if len(s.AllowPorts) == 0 || len(c.Mappings) != 2 || c.Server == "" {
		t.Errorf("examples lost settings: server %+v, client %+v", s, c)
	}
}

func writeConfig(t *testing.T, content string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rudp.yaml")
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil { // WriteFile's perm is subject to umask
		t.Fatal(err)
	}
	return path
}

// ports parses port ranges for test expectations.
func ports(s string) portRanges {
	r, err := parsePortRanges(s)
	if err != nil {
		panic(err)
	}
	return r
}
