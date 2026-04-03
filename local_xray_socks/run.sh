#!/usr/bin/with-contenv bashio
set -euo pipefail

SERVER="$(bashio::config 'server')"
PORT="$(bashio::config 'port')"
UUID="$(bashio::config 'uuid')"
SNI="$(bashio::config 'sni')"
FLOW="$(bashio::config 'flow')"
SOCKS_PORT="$(bashio::config 'socks_port')"
LOGLEVEL="$(bashio::config 'loglevel')"

if [ -z "${SERVER}" ]; then
  bashio::log.fatal "Option 'server' is required"
  exit 1
fi

if [ -z "${UUID}" ]; then
  bashio::log.fatal "Option 'uuid' is required"
  exit 1
fi

if [ -z "${SNI}" ]; then
  bashio::log.fatal "Option 'sni' is required"
  exit 1
fi

mkdir -p /usr/local/etc/xray /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log

USER_JSON="$(jq -n \
  --arg id "$UUID" \
  --arg flow "$FLOW" \
  '{id:$id, encryption:"none"} + (if $flow == "" then {} else {flow:$flow} end)')"

jq -n \
  --arg server "$SERVER" \
  --argjson port "$PORT" \
  --argjson socks_port "$SOCKS_PORT" \
  --arg sni "$SNI" \
  --arg loglevel "$LOGLEVEL" \
  --argjson user "$USER_JSON" \
  '{
    log: {
      loglevel: $loglevel,
      access: "/var/log/xray/access.log",
      error: "/var/log/xray/error.log"
    },
    inbounds: [
      {
        listen: "0.0.0.0",
        port: $socks_port,
        protocol: "socks",
        settings: {
          auth: "noauth",
          udp: true
        },
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls", "quic"]
        }
      }
    ],
    outbounds: [
      {
        protocol: "vless",
        settings: {
          vnext: [
            {
              address: $server,
              port: $port,
              users: [$user]
            }
          ]
        },
        streamSettings: {
          network: "tcp",
          security: "tls",
          tlsSettings: {
            serverName: $sni
          },
          sockopt: {
            tcpKeepAliveIdle: 45,
            tcpKeepAliveInterval: 15,
            tcpUserTimeout: 10000
          }
        },
        tag: "proxy"
      },
      {
        protocol: "freedom",
        tag: "direct"
      },
      {
        protocol: "blackhole",
        tag: "block"
      }
    ]
  }' > /usr/local/etc/xray/config.json

bashio::log.info "Starting Xray on SOCKS5 port ${SOCKS_PORT}"
if [ "${LOGLEVEL}" = "debug" ]; then
  bashio::log.info "Generated Xray config:"
  cat /usr/local/etc/xray/config.json
fi
exec /usr/local/bin/xray run -config /usr/local/etc/xray/config.json
