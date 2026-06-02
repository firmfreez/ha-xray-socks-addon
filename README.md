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

- `link`: Full `vless://...` URI. If set, the add-on parses it and overrides the manual connection fields below.
- `server`: VLESS server hostname or IP
- `port`: VLESS server port, usually `443`
- `uuid`: Client UUID from 3x-ui
- `sni`: TLS server name
- `flow`: Optional VLESS flow, leave empty unless your server requires it
- `fingerprint`: Optional TLS fingerprint such as `chrome`
- `alpn`: Optional ALPN list as comma-separated values, for example `h2,http/1.1`
- `socks_port`: Local SOCKS5 port exposed by the add-on
- `loglevel`: Xray log level

## Example

You can paste a full VLESS link like:

`vless://UUID@example.com:443?type=tcp&encryption=none&security=tls&fp=chrome&alpn=http%2F1.1&flow=xtls-rprx-vision`

When the add-on starts, Xray logs are written directly to the add-on log output so you can verify connections from the Home Assistant UI.
