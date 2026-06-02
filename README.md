# FirmFreez Home Assistant Add-ons

Home Assistant add-on repository with a local Xray-based SOCKS5 proxy for Raspberry Pi / Home Assistant OS.

## Included add-ons

- `local_xray_socks`: Runs Xray inside a Home Assistant add-on container and exposes a SOCKS5 port for LAN clients such as Keenetic.

## Add Repository To Home Assistant

In Home Assistant, open:

`Settings -> Add-ons -> Add-on Store -> Repositories`

Add the Git repository URL:

`https://github.com/firmfreez/ha-xray-socks-addon`

After that, install `Local Xray SOCKS`, fill in the VLESS settings, and start the add-on.

## Add-on Options

- `subscription_url`: VLESS subscription URL. Used when `link` is empty.
- `link`: Full `vless://...` URI. If set, the add-on parses it and overrides `subscription_url` and the manual connection fields below.
- `server`: VLESS server hostname or IP
- `port`: VLESS server port, usually `443`
- `uuid`: Client UUID from 3x-ui
- `sni`: TLS server name
- `flow`: Optional VLESS flow, leave empty unless your server requires it
- `fingerprint`: Optional TLS fingerprint such as `chrome`
- `alpn`: Optional ALPN list as comma-separated values, for example `h2,http/1.1`
- `socks_port`: Local SOCKS5 port exposed by the add-on (default: 1080, TCP and UDP)
- `loglevel`: Xray log level (default: `error` for cleaner logs)
  - Use `error` or `warning` for production
  - Use `info` or `debug` only for troubleshooting
  - Higher verbosity = more CPU usage and disk I/O

## Example

You can paste a full VLESS link like:

`vless://UUID@example.com:443?type=tcp&encryption=none&security=tls&fp=chrome&alpn=http%2F1.1&flow=xtls-rprx-vision`

Or use a subscription URL:

```yaml
subscription_url: "https://example.com/subscription"
link: ""
server: ""
uuid: ""
sni: ""
```

When the add-on starts, Xray logs are written directly to the add-on log output so you can verify connections from the Home Assistant UI.

## FAQ: "unknown command 5" Errors

**Q: Why do I see `rejected proxy/socks: unknown command 5` in logs?**

A: This is **harmless noise** from Keenetic's health checks or port scanning. It's not a Xray error:
- Actual TCP traffic works fine (you'll see `accepted tcp:... [proxy]` messages)
- These are malformed requests that get safely rejected before they reach Xray's core
- They don't affect performance or stability

**Q: Why is UDP disabled?**

A: Tests showed UDP on SOCKS inbound caused unnecessary complexity without real benefit:
- TCP SOCKS5 handles 99% of use cases including DNS
- Keenetic primarily uses TCP for all meaningful traffic
- UDP health checks were sent to TCP port anyway, causing confusion

**Q: Will sites stop working?**

A: No. DNS resolution works perfectly fine through TCP SOCKS5 (sniffing enabled). All applications work normally.

**To suppress these messages:** Set `loglevel` to `warning` or `error` in add-on options.

## Performance Optimizations (Built-in)

This add-on includes tuned defaults for a fast, low-noise SOCKS5 proxy:

**Network Tuning:**
- **BBR Congestion Control**: Uses BBR when the host kernel supports it
- **8MB Buffers**: Larger buffers for high-speed connections
- **TCP Fast Open**: Reduces TLS handshake by 1 RTT
- **TCP No Delay**: Minimizes packet buffering delays

**Memory & Connection Management:**
- **Large Buffer Pool**: 65KB per stream (3.25x increase)
- **Higher Connection Limits**: Tuned policy for multi-client setups
- **Optimized TCP Segment Size**: 1460 bytes for MTU 1500 networks

**DNS & Routing:**
- **DNS Caching**: Fast domain resolution with public DNS resolvers (8.8.8.8, 8.8.4.4, 1.1.1.1)
- **IP-based Domain Strategy**: Prevents DNS leaks
- **Keep-Alive: 600s**: Long connection timeout for stability

**Disabled for Speed:**
- Streaming stats collection (zero CPU overhead)
- User statistics tracking
- Unnecessary fallbacks

**Expected Performance:**
- **Latency**: Lower latency on networks where TCP tuning is supported
- **Throughput**: Better throughput on high-speed connections
- **Stability**: Longer keep-alive for idle connections
- **CPU Usage**: Lower overhead from disabled stats
