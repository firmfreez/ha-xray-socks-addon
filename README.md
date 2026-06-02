# FirmFreez Home Assistant Add-ons

Home Assistant add-on repository with a local Xray-based SOCKS5 proxy for Raspberry Pi / Home Assistant OS.

## Included add-ons

- `local_xray_socks`: Runs Xray inside a Home Assistant add-on container and exposes a SOCKS5 port for LAN clients such as Keenetic.

## Add Repository To Home Assistant

In Home Assistant, open:

`Settings -> Add-ons -> Add-on Store -> Repositories`

Add the Git repository URL:

`https://github.com/firmfreez/ha-xray-socks-addon`

After that, install `Local Xray SOCKS`, paste the VLESS link, and start the add-on.

## Add-on Options

- `link`: Full `vless://...` URI
- `loglevel`: Xray log level

## Example

You can paste a full VLESS link like:

`vless://UUID@example.com:443?type=tcp&encryption=none&security=tls&fp=chrome&alpn=http%2F1.1&flow=xtls-rprx-vision`

When the add-on starts, Xray logs are written directly to the add-on log output so you can verify connections from the Home Assistant UI.
