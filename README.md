# FirmFreez Home Assistant Add-ons

Home Assistant add-on repository with a local Xray-based SOCKS5 proxy for Raspberry Pi / Home Assistant OS.

## Included add-ons

- `local_xray_socks`: Runs Xray inside a Home Assistant add-on container and exposes a SOCKS5 port for LAN clients such as Keenetic.

## Add Repository To Home Assistant

In Home Assistant, open:

`Settings -> Add-ons -> Add-on Store -> Repositories`

Add the Git repository URL:

`https://github.com/firmfreez/ha-xray-socks-addon`

After that, install `Local Xray SOCKS`, choose the protocol, paste the matching connection settings, and start the add-on.

## Add-on Options

- `protocol`: `vless` or `amneziawg`
- `link`: Full `vless://...` URI. Used when `protocol` is `vless`.
- `amneziawg_config`: Full AmneziaWG/WireGuard-style client config. Used when `protocol` is `amneziawg`.
- `loglevel`: Xray log level

## VLESS Example

You can paste a full VLESS link like:

`vless://UUID@example.com:443?type=tcp&encryption=none&security=tls&fp=chrome&alpn=http%2F1.1&flow=xtls-rprx-vision`

## AmneziaWG Example

Set `protocol` to `amneziawg` and paste the client config into `amneziawg_config`:

```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.2/32
MTU = 1280
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 0
S2 = 0
H1 = 1-4294967295
H2 = 1-4294967295
H3 = 1-4294967295
H4 = 1-4294967295

[Peer]
PublicKey = SERVER_PUBLIC_KEY
PresharedKey = OPTIONAL_PRESHARED_KEY
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

In YAML mode, use a block scalar so Home Assistant keeps line breaks:

```yaml
protocol: amneziawg
link: ""
amneziawg_config: |
  [Interface]
  PrivateKey = CLIENT_PRIVATE_KEY
  Address = 10.0.0.2/32

  [Peer]
  PublicKey = SERVER_PUBLIC_KEY
  Endpoint = example.com:51820
  AllowedIPs = 0.0.0.0/0, ::/0
loglevel: info
```

When the add-on starts, Xray logs are written directly to the add-on log output so you can verify connections from the Home Assistant UI.
