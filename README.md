# simple-rudp

反向 UDP 端口转发（类似 frp 的 UDP 代理），但数据面只做**朴素的 UDP 转发**：不加密、不重传、不保序。UDP 本身怎么样，隧道就怎么样。

```
                     ┌──────────────── server ─────────────────┐
 WAN peer A ──udp──▶ │ :51820 (公网端口, 由 client 申请)         │
 WAN peer B ──udp──▶ │        │                                │
                     │        ▼                                │
                     │ :7001 UDP 隧道端口 (固定) ◀── UDP 隧道 ──┼──── client ──udp──▶ 127.0.0.1:51820
                     │ :7000 HTTP 控制 API ◀── (nginx) ◀── HTTP ┼────┘
                     └─────────────────────────────────────────┘
```

1. client 通过 HTTP(S) 控制 API 创建**会话**，用共享的 SecretKey 完成双向鉴权。
2. 鉴权通过后，client 在会话里申请公网端口，server 返回映射 ID 和 UDP 隧道端口。
3. client 从一个 UDP socket 向 server 的固定隧道端口发 `Register(映射 ID)`（同时也是 keepalive），server 由此知道 client 穿过 NAT 后的 UDP 地址。
4. WAN 发到公网端口的包，加 5 字节头（类型 + peer ID）后经隧道发给 client；client 为每个 peer 开一个本地 UDP socket 转给本地服务，回包原路返回。
5. client 定期发心跳续租。会话关闭（client 主动关闭，或 30 秒没有心跳）时，它的映射全部关闭；client 会自动重连（1s 起步、指数退避，上限 30s）。

控制 API 是普通的请求/响应式 HTTP，**不依赖任何 TCP 连接**，可以放在 nginx 等反向代理后面。

## 用法

```sh
go build -o rudp ./cmd/rudp
./rudp keygen                     # 生成一个随机 SecretKey，两端配置同一个

# 公网机器
RUDP_SECRET=... ./rudp server -control :7000 -tunnel :7001 -allow-ports 10000-20000,51820

# 内网机器（可以有多个 -map）
RUDP_SECRET=... ./rudp client -server http://example.com:7000 \
    -map 51820:127.0.0.1:51820 \
    -map 15353:[::1]:53
```

`build.sh` 会把静态、去掉符号表的二进制构建到 `dist/rudp-<os>-<arch>`，也支持交叉编译：`./build.sh linux/arm64`，或 `./build.sh all`。

### 配置文件

两个子命令都支持用 `-config` 指定 YAML 配置文件，键名与参数同名（`-` 写成 `_`）。带注释的完整示例见 [`examples/server.yaml`](examples/server.yaml) 和 [`examples/client.yaml`](examples/client.yaml)。

```yaml
# client.yaml
server: https://example.com/rudp
mappings:
  - "51820:127.0.0.1:51820"      # 与 -map 相同的写法
  - remote_port: 15353           # 或者分开写
    local: "[::1]:53"
keepalive: 10s
```

```sh
RUDP_SECRET=... ./rudp client -config client.yaml
```

- 优先级从低到高：默认值、配置文件、`RUDP_SECRET`（只影响密钥）、命令行参数。
- 命令行上的 `-map` / `-allow-ports` 会**整体替换**配置文件里的列表，而不是追加。
- 配置文件里出现未知的键会直接报错，拼写错误不会被悄悄忽略。
- 密钥写在配置文件里、而文件又能被其他用户访问时，会打印警告（建议 `chmod 600`）。
- `allow_ports` 可以写成列表 `[10000-20000, 51820]`，也可以写成字符串 `"10000-20000,51820"`。时长要带单位，如 `30s`、`2m`。

### 放在 nginx 后面

```nginx
location /rudp/ {
    proxy_pass http://127.0.0.1:7000/;   # 末尾的 / 会去掉 /rudp 前缀，这是必需的
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

```sh
./rudp server -control 127.0.0.1:7000 -tunnel :7001
./rudp client -server https://example.com/rudp -map 51820:127.0.0.1:51820
```

- nginx 只代理控制 API。**UDP 隧道端口（`-tunnel`）和公网端口要直接暴露**，不经过 nginx。
- client 默认把隧道发往 `-server` URL 里的主机；如果 rudp 不和 nginx 在同一个公网 IP 上，用 client 的 `-tunnel host:port` 指定。
- API 必须挂在代理的某个路径前缀下，并且代理要把前缀去掉（如上面 `proxy_pass` 末尾的 `/`）。签名只覆盖前缀之后的路径。

| server 参数 | 默认值 | 说明 |
|---|---|---|
| `-control` | `:7000` | HTTP 控制 API 地址 |
| `-tunnel` | `:7001` | UDP 隧道端口（固定） |
| `-secret` | `$RUDP_SECRET` | 共享密钥，**必填** |
| `-tls` | 关 | 控制 API 直接走 HTTPS，启动时生成自签证书（放在 nginx 后面时一般不需要） |
| `-bind` | 所有网卡 | 公网端口绑定的地址 |
| `-allow-ports` | 任意 | 允许 client 申请的端口 |
| `-session-timeout` | `30s` | 会话多久没有心跳就关闭（含其所有端口） |
| `-peer-timeout` | `2m` | WAN peer 空闲多久后遗忘 |

| client 参数 | 默认值 | 说明 |
|---|---|---|
| `-server` | 必填 | 控制 API 的 URL，如 `http://host:7000`、`https://example.com/rudp`；只写 `host:port` 等于 `http://host:port` |
| `-map` | 必填 | `公网端口:本地host:本地端口`，可重复；公网端口为 0 时由 server 分配 |
| `-secret` | `$RUDP_SECRET` | 共享密钥，**必填**，与 server 相同 |
| `-insecure` | 关 | 不校验 TLS 证书，用于 server 或 nginx 的自签证书 |
| `-tunnel` | `-server` 的主机 + server 告知的端口 | 隧道地址 |
| `-keepalive` | `10s` | 隧道 keepalive 间隔；连续 3 个间隔没回应就重连 |
| `-peer-timeout` | `2m` | 本地 socket 空闲多久后关闭 |

两边都支持 `-v` 打开 debug 日志。建议用环境变量传密钥，避免出现在 `ps` 里。

## 控制 API

| 请求 | 签名 | 成功 | 说明 |
|---|---|---|---|
| `POST /v1/sessions` `{version, nonce}` | 否 | `201 {session, nonce, proof}` | 创建待鉴权会话；server 证明自己知道密钥 |
| `POST /v1/sessions/{id}/auth` `{proof}` | 否 | `200 {lease_ms}` | client 证明自己知道密钥，会话生效 |
| `POST /v1/sessions/{id}/heartbeat` | **是** | `204` | 续租 |
| `POST /v1/sessions/{id}/mappings` `{port}` | **是** | `201 {id, port, tunnel_port}` | 打开公网端口 |
| `DELETE /v1/sessions/{id}` | **是** | `204` | 关闭会话及其端口 |

出错时返回非 2xx 和 `{"error": "..."}`：未鉴权/签名错误 401，会话不存在或已过期 404，端口不在白名单 403，端口被占用 409。

- **鉴权**：`proof = HMAC-SHA256(SecretKey, 角色标签 ‖ client nonce ‖ server nonce ‖ 会话 ID)`。密钥本身不上网。client 先验证 server 的证明，再交出自己的。每个会话只有一次鉴权机会。
- **60 秒期限**：会话创建后 60 秒内没有通过鉴权就会被丢弃；在此之前它除了鉴权什么都做不了。未鉴权会话最多同时存在 1024 个。
- **请求签名**：鉴权后双方各自算出会话密钥 `HMAC(SecretKey, 标签 ‖ 两个 nonce ‖ 会话 ID)`。之后每个请求带 `Rudp-Seq`（必须递增）和 `Rudp-Signature`（对方法、路径、序号、body 哈希的 HMAC）。因此请求**不能伪造、不能重放、不能篡改**，即使走明文 HTTP、或者经过终止 TLS 的代理也一样；nginx 日志里也只有不敏感的会话 ID，没有可以冒用的令牌。
- **租约**：每个有效的签名请求都会续租；client 每租期发 3 次心跳。超过 `-session-timeout` 没有请求，会话和它的端口一起关闭。client 正常退出时会 `DELETE` 会话，端口立即释放。

## 隧道协议（UDP）

第一个字节是类型：

| 包 | 方向 | 格式 |
|---|---|---|
| Register | client → server | `0x01` + 16 字节映射 ID |
| Ack | server → client | `0x02` |
| Data | 双向 | `0x03` + 4 字节 peer ID (大端) + 原始 payload |

Data 包不带映射 ID，server 按来源地址识别 client，所以每包只多 5 字节。未知映射的 Register 不会得到任何回应。

## 注意事项

- **数据面不加密**：UDP 隧道里的 payload 和映射 ID 都是明文。适合承载本身已加密的协议（WireGuard 等）。能看到隧道 UDP 流量的人（路径上的中间人）可以重放 Register 把隧道劫持到自己那里；路径外的攻击者做不到。控制 API 不受此影响：没有密钥就开不了端口。
- **HTTPS 的作用**：控制 API 的安全性来自签名而不是 TLS，所以自签证书配 `-insecure` 不会让人冒用你的会话。TLS 提供的是控制流量的保密性（例如映射 ID 不在 HTTP 里明文出现）。
- **MTU**：隧道每包多 5 字节。如果内层包已经顶满路径 MTU，隧道段会发生 IP 分片（能用，但效率差）。WireGuard 默认 MTU 1420，在 IPv4 路径上有足够余量。
- **本地服务看到的来源地址**是 client 本机的随机端口（每个 WAN peer 一个），不是 WAN 的真实 IP，和 NAT 后的效果一样。
- **NAT 重绑定**：client 的公网 UDP 地址变化后，到下一次 keepalive（≤ `-keepalive`）之前 client → server 方向的包会被丢弃。
- **client 崩溃后重连**：来不及 `DELETE` 时，旧会话要等租约到期（≤ `-session-timeout`）才释放端口，这期间重连会收到 409，client 会自动重试直到成功。
- 每个活跃 peer 在 client 端占一个 socket 和一个 64 KiB 读缓冲。

## 开发

```sh
go test -race ./...
```

`cmd/rudp` 的测试覆盖配置文件解析和优先级。`internal/e2e` 在回环地址上跑真实的 server、client 和 echo 服务，覆盖直连 HTTP/HTTPS、反向代理（带前缀、每个请求一条新连接）、控制 API（伪造/重放/篡改）、60 秒鉴权期限和租约到期（测试里缩短为 500ms）、错误密钥、证书校验。
