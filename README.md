# FirmFreez Home Assistant Add-ons

Home Assistant add-on repository with a local Xray-based SOCKS5 proxy for Raspberry Pi / Home Assistant OS.

## Included add-ons

- `local_xray_socks`: Runs Xray inside a Home Assistant add-on container and exposes a SOCKS5 port for LAN clients such as Keenetic.


## Upgrade to 0.6.1

The existing `local_xray_socks` add-on now includes a single **VPN Manager**
Ingress panel for VLESS, AmneziaWG, OpenVPN and Check Point. Its slug and primary
port 1080 are unchanged. Update the existing installation from the same repository;
do not uninstall it or install a second add-on.

On first launch, legacy options are imported once into named profiles. The active
connection keeps 1080 and autostarts; other saved profiles remain stopped.
After migration, use the panel to manage settings. Legacy YAML options below
remain for migration compatibility only.

The ARM64 image builds successfully. HA OS networking and real VPN connections
still need verification on the target installation. See [upgrade and setup instructions](local_xray_socks/DOCS.md),
including new permissions, backup, DNS and protocol limitations.

## Add Repository To Home Assistant

In Home Assistant, open:

`Settings -> Add-ons -> Add-on Store -> Repositories`

Add the Git repository URL:

`https://github.com/firmfreez/ha-xray-socks-addon`

After that, install `Local Xray SOCKS`, start the add-on, open its Web UI, and add a named connection. Existing installations should use Update instead of reinstalling.

## Legacy Add-on Options (0.5.x / one-time migration)

- `protocol`: `vless` or `amneziawg`
- `link`: Full `vless://...` URI. Used when `protocol` is `vless`.
- `amneziawg_profile`: Active AmneziaWG configuration slot, from `1` to `4`.
- `amneziawg_config`: Full AmneziaWG/WireGuard-style client config for profile 1.
- `amneziawg_config_2`, `amneziawg_config_3`, `amneziawg_config_4`: Additional AmneziaWG configuration profiles.
- `loglevel`: Xray log level
- `watchdog_enabled`: Check connectivity through SOCKS every 30 seconds (default
  `true`). After three consecutive failed rounds, restart both VPN processes
  with a 30-second delay. Process exits are monitored even when this is `false`.
- `watchdog_urls`: Comma-separated HTTP(S) URLs for connectivity checks. Defaults
  to Cloudflare trace and Google generate_204. Each request goes through the VPN
  and has a 10-second timeout; one successful URL makes the round successful.
  Choose reachable URLs for your network, especially for split-tunnel profiles.

Recovery recreates the AmneziaWG interface and resolves its endpoint again.
Existing proxy connections are interrupted and clients must reconnect. During
an upstream outage, recovery repeats until connectivity returns. The Home
Assistant Watchdog switch additionally monitors the SOCKS listening port and
can restart the add-on if startup fails.

If an AmneziaWG profile omits `PersistentKeepalive`, the add-on uses 25 seconds
to keep NAT mappings alive during idle periods. An explicit `0` is preserved.
Logs report process exits, failed connectivity checks, and AWG handshake/transfer
counters before recovery. Generated Xray configuration is no longer printed
at debug level because it contains connection credentials.

## VLESS Example

You can paste a full VLESS link like:

`vless://UUID@example.com:443?type=tcp&encryption=none&security=tls&fp=chrome&alpn=http%2F1.1&flow=xtls-rprx-vision`

## AmneziaWG Example

Set `protocol` to `amneziawg`, select `amneziawg_profile`, and paste the client
config into the corresponding configuration slot. Profile 1 uses the original
`amneziawg_config` option for backward compatibility.

```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.2/32
MTU = 1280
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 76
S2 = 47
S3 = 33
S4 = 12
H1 = 1-4294967295
H2 = 1-4294967295
H3 = 1-4294967295
H4 = 1-4294967295
HeaderProtectionKey = SHARED_HEADER_PROTECTION_KEY
ContentPaddingAddition = 10-100
RandomTrailers = on
DisableCookies = on
RekeyAfterTime = 120-180
RekeyTimeout = 5-10
RejectAfterTime = 180-240
KeepaliveTimeout = 10-20
MaxHandshakeAttempts = 20

[Peer]
PublicKey = SERVER_PUBLIC_KEY
PresharedKey = OPTIONAL_PRESHARED_KEY
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

AmneziaWG 3.1 configurations are supported, including header protection,
content padding, randomized handshake trailers, disabled cookies, and custom
timing ranges. When `HeaderProtectionKey` is present, all `S1`-`S4` values must
be at least 12 as required by the AmneziaWG engine.

In YAML mode, use a block scalar so Home Assistant keeps line breaks:

```yaml
protocol: amneziawg
link: ""
amneziawg_profile: "1"
amneziawg_config: |
  [Interface]
  PrivateKey = CLIENT_PRIVATE_KEY
  Address = 10.0.0.2/32

  [Peer]
  PublicKey = SERVER_PUBLIC_KEY
  Endpoint = example.com:51820
  AllowedIPs = 0.0.0.0/0, ::/0
amneziawg_config_2: ""
amneziawg_config_3: ""
amneziawg_config_4: ""
loglevel: info
```

To switch servers, change only `amneziawg_profile` to `1`, `2`, `3`, or `4`
and restart the add-on. The other saved configurations remain unchanged.

At startup, the add-on logs both the bundled engine version and the detected
protocol profile. A configuration containing `RandomTrailers` or
`DisableCookies` is reported as `3.1`; configurations with other AWG 3
parameters are reported as `3.0`; older configurations are reported as
`legacy 1.x/2.x`. No private or shared keys are included in these messages.

When the add-on starts, Xray logs are written directly to the add-on log output so you can verify connections from the Home Assistant UI.
