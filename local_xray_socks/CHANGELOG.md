# 0.8.1

- Answer standard AnyConnect secondary-password and challenge fields with the
  configured MFA value (push by default), unless an explicit MFA form is selected.
- Stop automatic recovery when AnyConnect reports unresolved interactive input
  or incomplete authentication; explain that a repeated Password prompt can be
  either MFA or rejection of the primary credentials.
- Never automatically resubmit the primary password after rejection.

# 0.8.0

- Add Cisco AnyConnect profiles through OpenConnect: password login, server-driven
  mobile push MFA, auth group and optional second-factor form response.
- Isolate AnyConnect routes, resolver and vpnc state per profile; publish server DNS
  and wait for the tunnel hook before reporting the connection as started.
- Add per-profile reconnect switch and either a finite retry limit or Always.
  Centralize recovery for VLESS/AmneziaWG so internal restarts cannot bypass limits.
- Add opt-in per-profile disconnect pushes to selected Home Assistant mobile app
  notification services. One notification per outage; manual stops do not notify.
- Enable Home Assistant Core API access through Supervisor. VPN child processes
  no longer inherit the Supervisor bearer token.

# 0.7.8

- Start and recover profiles independently; unavailable Check Point discovery or
  endpoint DNS no longer blocks other profiles or the Ingress panel.
- Retry DNS/startup failures and exited processes with a 5–300 second backoff.
  Manual stop cancels pending recovery; stale probes cannot overwrite a new attempt.
- Reconnect OpenVPN/Check Point after three failed checks of the configured work
  site. Recognized authentication/certificate failures require manual correction.
- Bound endpoint DNS lookups, wait for concurrent firewall updates, and preserve
  per-profile routes, processes and corporate DNS isolation during recovery.
- Show retry status/countdown and timestamp lifecycle events in the add-on log.
- Skip damaged saved profiles without stopping healthy ones or deleting data.

# 0.7.7

- Use neutral example names and server addresses in the Check Point UI and tests.
- Remove server-specific tunnel recommendations.

# 0.7.6

- Fix corporate DNS forwarding when the VPN permits UDP DNS but blocks TCP DNS.
- Retry truncated UDP replies over TCP and validate the upstream DNS question.

# 0.7.5

- Replace connection cards with a responsive list and a secondary actions menu.
- Keep only the relevant connect/disconnect button visible in each row.

- Fix Check Point startup on Home Assistant with read-only /proc/sys.
- Expose network sysctls only inside the profile’s network and mount namespaces.
- Test Check Point sysctl setup with the add-on capabilities instead of privileged Docker.

# 0.7.4

- Add a dedicated Personal Certificate setup with .p12/.pfx upload.
- Discover gateway login methods and automatically select a unique matching method.
- Apply Check Point DNS in a private resolver without changing container DNS.
- Keep manual DNS overrides and separate certificate/password authentication.

# 0.7.3

- Apply OpenVPN-provided IPv4 DNS automatically when the tunnel connects.
- Refresh SOCKS and LAN DNS forwarding on reconnect; manual DNS takes precedence.
- Show effective corporate DNS in the panel and fail closed when it is absent.

# 0.7.2

- Accept explicit `tls-client` OpenVPN configurations.
- Expand supported client directives for TLS certificate verification, keepalive,
  reconnects, routing, addressing, MTU, replay windows and transport options.

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
