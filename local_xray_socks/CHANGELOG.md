# 0.7.1

- Accept OpenVPN `ignore-unknown-option` and the cross-platform
  `block-outside-dns` option during import.
- Support `setenv opt` for allowed optional directives while preserving
  validation of scripts and file paths.

# 0.7.0

- Hide obsolete Home Assistant options; manage connections in VPN Manager.
- Show saved VLESS/AWG/OpenVPN configuration and populate the edit form.
- List only free ports; every VPN type can use any port from 1080–1088.
- Support SOCKS5 TCP and UDP for all profiles through isolated Xray proxies.
- Replace the repeated site prompt with a one-click check, saved target,
  automatic checks, and a visible last result and timestamp.
- Add a scroll-to-bottom button and follow new log lines while at the bottom.
- Support VLESS TCP, WebSocket, gRPC, XHTTP, HTTPUpgrade and mKCP share links,
  including TLS and REALITY settings instead of forcing TCP+TLS.
- Preserve per-profile environment through the HA container launcher and avoid
  writing read-only sysctls when forwarding is already enabled.
- Verify ARM64 build, synthetic TCP/UDP tunnel traffic and tunnel-loss blocking.

# 0.6.1

- Fix Home Assistant installation failing with `microsocks (no such package)`:
  build pinned microsocks 1.0.5 from source instead of installing it with apk.
- Remove the GitHub Actions validation workflow.
- Successfully build the ARM64 image locally and verify bundled VPN binaries.

# 0.6.0

- Add a single Home Assistant Ingress panel for VLESS, AmneziaWG, OpenVPN and
  Check Point profiles, with names, import, start/stop, logs and site checks.
- Keep the existing `local_xray_socks` slug and primary SOCKS port 1080.
- Import legacy options once, preserving the active connection, saved AWG
  profiles, watchdog configuration and a private backup of the original options.
- Use separate runtime files and AWG interface names for each personal profile;
  additional connections run in separate network namespaces.
- Add TCP SOCKS ports 1081–1088 and per-profile corporate DNS forwarding.
- Monitor the panel instead of port 1080 so intentionally stopping a VPN does
  not cause Home Assistant to restart the add-on.
- Additional VPN isolation requires SYS_ADMIN and disables AppArmor in this
  experimental implementation. Review DOCS.md before updating.

Validation: unit tests and local browser checks. ARM64 container build, HA OS
network isolation and real corporate VPN authentication are not yet verified.
UDP remains available for the primary VLESS/AmneziaWG profile; additional
profiles expose TCP SOCKS only. Interactive MFA/SSO is not implemented.
