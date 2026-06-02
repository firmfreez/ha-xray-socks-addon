#!/usr/bin/with-contenv bashio
set -euo pipefail

urldecode() {
  local value="${1//+/ }"
  printf '%b' "${value//%/\\x}"
}

parse_vless_link() {
  local link="$1"
  local body query main creds hostport key_value key raw_key raw_value decoded_key decoded_value
  local transport_type="" security_mode="" encryption_mode=""

  if [[ "${link}" != vless://* ]]; then
    bashio::log.fatal "Option 'link' must start with vless://"
    exit 1
  fi

  body="${link#vless://}"
  main="${body%%#*}"
  query=""

  if [[ "${main}" == *"?"* ]]; then
    query="${main#*\?}"
    main="${main%%\?*}"
  fi

  creds="${main%@*}"
  hostport="${main#*@}"

  if [[ -z "${creds}" || "${creds}" == "${main}" ]]; then
    bashio::log.fatal "Option 'link' does not contain a UUID before @"
    exit 1
  fi

  if [[ "${hostport}" != *":"* ]]; then
    bashio::log.fatal "Option 'link' does not contain host:port after @"
    exit 1
  fi

  UUID="$(urldecode "${creds}")"
  SERVER="$(urldecode "${hostport%:*}")"
  PORT="$(urldecode "${hostport##*:}")"

  IFS='&' read -r -a query_params <<< "${query}"
  for key_value in "${query_params[@]}"; do
    [ -n "${key_value}" ] || continue
    key="${key_value%%=*}"
    raw_value=""
    if [[ "${key_value}" == *"="* ]]; then
      raw_value="${key_value#*=}"
    fi
    decoded_key="$(urldecode "${key}")"
    decoded_value="$(urldecode "${raw_value}")"

    case "${decoded_key}" in
      type) transport_type="${decoded_value}" ;;
      security) security_mode="${decoded_value}" ;;
      encryption) encryption_mode="${decoded_value}" ;;
      sni) SNI="${decoded_value}" ;;
      flow) FLOW="${decoded_value}" ;;
      fp) FINGERPRINT="${decoded_value}" ;;
      alpn) ALPN="${decoded_value}" ;;
    esac
  done

  if [ -n "${transport_type}" ] && [ "${transport_type}" != "tcp" ]; then
    bashio::log.fatal "Unsupported VLESS transport type '${transport_type}'. This add-on supports only type=tcp"
    exit 1
  fi

  if [ -n "${security_mode}" ] && [ "${security_mode}" != "tls" ]; then
    bashio::log.fatal "Unsupported VLESS security '${security_mode}'. This add-on supports only security=tls"
    exit 1
  fi

  if [ -n "${encryption_mode}" ] && [ "${encryption_mode}" != "none" ]; then
    bashio::log.fatal "Unsupported VLESS encryption '${encryption_mode}'. Expected encryption=none"
    exit 1
  fi

  if [ -z "${SNI}" ]; then
    SNI="${SERVER}"
  fi
}

LINK="$(bashio::config 'link')"
SOCKS_PORT="$(bashio::config 'socks_port')"
LOGLEVEL="$(bashio::config 'loglevel')"

SERVER=""
PORT=""
UUID=""
SNI=""
FLOW=""
FINGERPRINT=""
ALPN=""

if [ -z "${LINK}" ]; then
  bashio::log.fatal "Option 'link' is required"
  exit 1
fi

parse_vless_link "${LINK}"

if [ -z "${SERVER}" ]; then
  bashio::log.fatal "Option 'link' does not contain a server"
  exit 1
fi

if [ -z "${UUID}" ]; then
  bashio::log.fatal "Option 'link' does not contain a UUID"
  exit 1
fi

if [ -z "${SNI}" ]; then
  bashio::log.fatal "Option 'link' does not contain an SNI and server fallback failed"
  exit 1
fi

mkdir -p /usr/local/etc/xray

USER_JSON="$(jq -n \
  --arg id "$UUID" \
  --arg flow "$FLOW" \
  '{id:$id, encryption:"none"} + (if $flow == "" then {} else {flow:$flow} end)')"

TLS_SETTINGS_JSON="$(jq -n \
  --arg sni "$SNI" \
  --arg fingerprint "$FINGERPRINT" \
  --arg alpn "$ALPN" \
  '{
    serverName: $sni
  }
  + (if $fingerprint == "" then {} else {fingerprint: $fingerprint} end)
  + (if $alpn == "" then {} else {alpn: ($alpn | split(","))} end)')"

jq -n \
  --arg server "$SERVER" \
  --argjson port "$PORT" \
  --argjson socks_port "$SOCKS_PORT" \
  --arg loglevel "$LOGLEVEL" \
  --argjson user "$USER_JSON" \
  --argjson tls_settings "$TLS_SETTINGS_JSON" \
  '{
    log: {
      loglevel: $loglevel,
      access: "/dev/stdout",
      error: "/dev/stderr"
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
          tlsSettings: $tls_settings,
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

bashio::log.info "Resolved VLESS target ${SERVER}:${PORT} with SNI ${SNI}"
if [ -n "${FLOW}" ]; then
  bashio::log.info "Using VLESS flow ${FLOW}"
fi
if [ -n "${FINGERPRINT}" ]; then
  bashio::log.info "Using TLS fingerprint ${FINGERPRINT}"
fi
if [ -n "${ALPN}" ]; then
  bashio::log.info "Using ALPN ${ALPN}"
fi
bashio::log.info "Starting Xray on SOCKS5 port ${SOCKS_PORT}"
if [ "${LOGLEVEL}" = "debug" ]; then
  bashio::log.info "Generated Xray config:"
  cat /usr/local/etc/xray/config.json
fi
exec /usr/local/bin/xray run -config /usr/local/etc/xray/config.json
