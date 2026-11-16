# simple-rudp

Reverse UDP port forwarding (like frp's UDP proxy), except that the data plane is **plain UDP forwarding**: no encryption, no retransmission, no ordering. The tunnel behaves just like UDP itself.

```
                     ┌──────────────────── server ────────────────────┐
 WAN peer A ──udp──▶ │ :51820 public port, requested by the client    │
 WAN peer B ──udp──▶ │    │                                           │
                     │    ▼                                           │
                     │ :7001 UDP tunnel port (fixed) ◀── UDP tunnel ──┼──── client ──udp──▶ 127.0.0.1:51820
                     │ :7000 HTTP control API ◀── (nginx) ◀── HTTP ───┼────┘
                     └────────────────────────────────────────────────┘
```

1. The client creates a **session** over the HTTP(S) control API, and client and server authenticate each other with a shared SecretKey.
2. Once authenticated, the client requests public ports in the session; for each one, the server returns a mapping ID and the UDP tunnel port.
3. From a UDP socket, the client sends `Register(mapping ID)` to the server's fixed tunnel port (it doubles as a keepalive). This tells the server the client's UDP address as seen through NAT.
4. Packets that WAN peers send to a public port get a 5-byte header (type + peer ID) and travel through the tunnel to the client. The client opens one local UDP socket per peer to pass them to the local service; replies return the same way.
5. The client sends heartbeats to renew its lease. When the session closes (the client closes it, or 30 seconds pass without a heartbeat), all its mappings close; the client reconnects automatically (after 1s at first, backing off exponentially up to 30s).

The control API is plain request/response HTTP and **does not depend on any TCP connection**, so it can sit behind a reverse proxy such as nginx.

## Usage

```sh
go build -o rudp ./cmd/rudp
./rudp keygen                     # prints a random SecretKey; configure the same one on both ends

# Public machine
RUDP_SECRET=... ./rudp server -control :7000 -tunnel :7001 -allow-ports 10000-20000,51820

# Private machine (-map can be repeated)
RUDP_SECRET=... ./rudp client -server http://example.com:7000 \
    -map 51820:127.0.0.1:51820 \
    -map 15353:[::1]:53
```

`build.sh` builds static, stripped binaries into `dist/rudp-<os>-<arch>`. It also cross-compiles: `./build.sh linux/arm64` or `./build.sh all`.

### Config files

Both subcommands read a YAML config file given with `-config`. Its keys are the flag names, with `-` written as `_`. See [`examples/server.yaml`](examples/server.yaml) and [`examples/client.yaml`](examples/client.yaml) for complete, commented examples.

```yaml
# client.yaml
server: https://example.com/rudp
mappings:
  - "51820:127.0.0.1:51820"      # same syntax as -map
  - remote_port: 15353           # or as separate fields
    local: "[::1]:53"
keepalive: 10s
```

```sh
RUDP_SECRET=... ./rudp client -config client.yaml
```

- Precedence, from lowest to highest: defaults, the config file, `RUDP_SECRET` (for the secret key only), flags.
- `-map` and `-allow-ports` on the command line **replace** the list from the config file rather than adding to it.
- Unknown keys in a config file are an error, so typos are never silently ignored.
- When the config file holds the secret key and other users can access the file, rudp prints a warning (`chmod 600` it).
- `allow_ports` can be a list, `[10000-20000, 51820]`, or a string, `"10000-20000,51820"`. Durations need a unit, such as `30s` or `2m`.

### Behind nginx

```nginx
location /rudp/ {
    proxy_pass http://127.0.0.1:7000/;   # the trailing / strips the /rudp prefix, which is required
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

```sh
./rudp server -control 127.0.0.1:7000 -tunnel :7001
./rudp client -server https://example.com/rudp -map 51820:127.0.0.1:51820
```

- nginx proxies only the control API. **The UDP tunnel port (`-tunnel`) and the public ports must be exposed directly**, not through nginx.
- By default the client sends tunnel traffic to the host in the `-server` URL. If rudp is not on the same public IP as nginx, set the tunnel address with the client's `-tunnel host:port`.
- The proxy can serve the API under a path prefix, but must strip the prefix before passing requests on (as the trailing `/` of `proxy_pass` does above). Signatures cover only the path after the prefix.

| Server flag | Default | Description |
|---|---|---|
| `-control` | `:7000` | Address of the HTTP control API |
| `-tunnel` | `:7001` | UDP tunnel port (fixed) |
| `-secret` | `$RUDP_SECRET` | Shared secret key, **required** |
| `-tls` | off | Serve the control API over HTTPS directly, with a self-signed certificate generated at startup (usually unnecessary behind nginx) |
| `-bind` | all interfaces | Address to open public ports on |
| `-allow-ports` | any | Ports clients may request |
| `-session-timeout` | `30s` | Close a session, with all its ports, after this long without a heartbeat |
| `-peer-timeout` | `2m` | Forget WAN peers idle for this long |

| Client flag | Default | Description |
|---|---|---|
| `-server` | required | URL of the control API, such as `http://host:7000` or `https://example.com/rudp`; a bare `host:port` means `http://host:port` |
| `-map` | required | `remotePort:localHost:localPort`, repeatable; with a remote port of 0, the server picks the port |
| `-secret` | `$RUDP_SECRET` | Shared secret key, **required**, the same as the server's |
| `-insecure` | off | Skip TLS certificate verification, for a self-signed certificate on the server or nginx |
| `-tunnel` | host of `-server`, port announced by the server | Tunnel address |
| `-keepalive` | `10s` | Tunnel keepalive interval; the client reconnects after 3 intervals without a response |
| `-peer-timeout` | `2m` | Close local sockets idle for this long |

Both commands take `-v` for debug logging. Pass the secret key in the environment variable, so it does not show up in `ps`.

## Control API

| Request | Signed | Success | Description |
|---|---|---|---|
| `POST /v1/sessions` `{version, nonce}` | no | `201 {session, nonce, proof}` | Creates an unauthenticated session; the server proves it knows the key |
| `POST /v1/sessions/{id}/auth` `{proof}` | no | `200 {lease_ms}` | The client proves it knows the key, and the session becomes active |
| `POST /v1/sessions/{id}/heartbeat` | **yes** | `204` | Renews the lease |
| `POST /v1/sessions/{id}/mappings` `{port}` | **yes** | `201 {id, port, tunnel_port}` | Opens a public port |
| `DELETE /v1/sessions/{id}` | **yes** | `204` | Closes the session and its ports |

Errors return a non-2xx status and `{"error": "..."}`: 401 for an unauthenticated session or a bad signature, 404 for a session that does not exist or has expired, 403 for a port not on the allow list, 409 for a port already in use.

- **Authentication**: `proof = HMAC-SHA256(SecretKey, role label ‖ client nonce ‖ server nonce ‖ session ID)`. The key itself never crosses the network. The client checks the server's proof before handing over its own. Each session gets one authentication attempt.
- **60-second deadline**: A session that has not authenticated within 60 seconds of its creation is dropped; until it authenticates, it can do nothing else. At most 1024 unauthenticated sessions can exist at once.
- **Request signing**: After authentication, each side derives the session key `HMAC(SecretKey, label ‖ both nonces ‖ session ID)`. Every later request carries `Rudp-Seq` (which must increase) and `Rudp-Signature` (an HMAC of the method, path, sequence number and body hash). Requests therefore **cannot be forged, replayed or tampered with**, even over plain HTTP or through a proxy that terminates TLS. nginx logs hold only the session ID, which is not sensitive: there is no token anyone could reuse.
- **Lease**: Every valid signed request renews the lease, and the client sends 3 heartbeats per lease period. After `-session-timeout` without a request, the session closes along with its ports. A client that exits normally `DELETE`s its session, which frees its ports at once.

## Tunnel protocol (UDP)

The first byte is the packet type:

| Packet | Direction | Format |
|---|---|---|
| Register | client → server | `0x01` + 16-byte mapping ID |
| Ack | server → client | `0x02` |
| Data | both | `0x03` + 4-byte peer ID (big-endian) + raw payload |

Data packets carry no mapping ID: the server identifies the client by its source address, so each packet grows by only 5 bytes. A Register for an unknown mapping gets no response.

## Caveats

- **The data plane is not encrypted**: payloads and mapping IDs cross the UDP tunnel in the clear, so it suits protocols that are encrypted already, such as WireGuard. Anyone who can see the tunnel's UDP traffic (an on-path attacker) can replay a Register to hijack the tunnel; off-path attackers cannot. The control API is not affected: without the key, nobody can open ports.
- **What HTTPS is for**: The control API's security comes from its signatures, not from TLS, so using a self-signed certificate with `-insecure` does not let anyone take over your session. What TLS adds is confidentiality for the control traffic (mapping IDs, for example, are not sent in clear text over HTTP).
- **MTU**: The tunnel adds 5 bytes to every packet. If the inner packets already fill the path MTU, the tunnel leg is IP-fragmented (which works, but inefficiently). WireGuard's default MTU of 1420 leaves enough room on IPv4 paths.
- **The source address local services see** is a random port on the client machine (one per WAN peer), not the peer's real WAN IP, just like behind NAT.
- **NAT rebinding**: When the client's public UDP address changes, client → server packets are dropped until the next keepalive (within `-keepalive`).
- **Reconnecting after a client crash**: When the client had no chance to `DELETE` its session, the old session keeps its ports until its lease expires (within `-session-timeout`). Reconnecting in the meantime gets 409, and the client keeps retrying until it succeeds.
- Each active peer takes a socket and a 64 KiB read buffer on the client.

## Development

```sh
go test -race ./...
```

The tests in `cmd/rudp` cover config file parsing and precedence. `internal/e2e` runs a real server, client and echo service on loopback, covering plain HTTP and HTTPS, a reverse proxy (with a prefix, and a new connection for every request), the control API (forged, replayed and tampered requests), the 60-second authentication deadline and lease expiry (shortened to 500ms in the tests), a wrong key, and certificate verification.
