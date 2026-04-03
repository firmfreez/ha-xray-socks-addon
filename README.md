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

- `server`: VLESS server hostname or IP
- `port`: VLESS server port, usually `443`
- `uuid`: Client UUID from 3x-ui
- `sni`: TLS server name
- `flow`: Optional VLESS flow, leave empty unless your server requires it
- `socks_port`: Local SOCKS5 port exposed by the add-on
- `loglevel`: Xray log level
