#!/usr/bin/with-contenv bashio
set -euo pipefail

urldecode() {
  local value="${1//+/ }"
  printf '%b' "${value//%/\\x}"
}

extract_vless_link() {
  local content="$1"
  printf '%s\n' "${content}" | tr '\r' '\n' | grep -m1 '^vless://' || true
}

fetch_subscription_link() {
  local subscription_url="$1"
  local content encoded decoded link padding

  bashio::log.info "Fetching VLESS subscription"
  content="$(curl -fsSL --connect-timeout 10 --max-time 30 "${subscription_url}")" || {
    bashio::log.fatal "Failed to fetch subscription URL"
    exit 1
  }

  link="$(extract_vless_link "${content}")"
  if [ -n "${link}" ]; then
    printf '%s' "${link}"
    return 0
  fi

  encoded="$(printf '%s' "${content}" | tr -d '\r\n ')"
  padding=$(( ${#encoded} % 4 ))
  if [ "${padding}" -eq 2 ]; then
    encoded="${encoded}=="
  elif [ "${padding}" -eq 3 ]; then
    encoded="${encoded}="
  fi

  decoded="$(printf '%s' "${encoded}" | base64 -d 2>/dev/null || true)"
  link="$(extract_vless_link "${decoded}")"
  if [ -n "${link}" ]; then
    printf '%s' "${link}"
    return 0
  fi

  bashio::log.fatal "Subscription does not contain a supported vless:// link"
  exit 1
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
SUBSCRIPTION_URL="$(bashio::config 'subscription_url')"
SERVER="$(bashio::config 'server')"
PORT="$(bashio::config 'port')"
UUID="$(bashio::config 'uuid')"
SNI="$(bashio::config 'sni')"
FLOW="$(bashio::config 'flow')"
FINGERPRINT="$(bashio::config 'fingerprint')"
ALPN="$(bashio::config 'alpn')"
SOCKS_PORT="$(bashio::config 'socks_port')"
LOGLEVEL="$(bashio::config 'loglevel')"

if [ -z "${LINK}" ] && [ -n "${SUBSCRIPTION_URL}" ]; then
  LINK="$(fetch_subscription_link "${SUBSCRIPTION_URL}")"
fi

if [ -n "${LINK}" ]; then
  parse_vless_link "${LINK}"
fi

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
    dns: {
      servers: [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1"
      ],
      hosts: {},
      clientIp: null,
      queryStrategy: "UseIPv4",
      disableCache: false,
      disableFallback: false,
      tag: "dns_resolver"
    },
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        {
          type: "field",
          inboundTag: ["socks"],
          port: 53,
          network: "udp",
          outboundTag: "dns_out"
        },
        {
          type: "field",
          domain: [
            "geosite:geolocation-!cn"
          ],
          outboundTag: "proxy"
        }
      ]
    },
    inbounds: [
      {
        listen: "0.0.0.0",
        port: $socks_port,
        protocol: "socks",
        settings: {
          auth: "noauth",
          udp: true,
          userLevel: 0
        },
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls", "quic"],
          metadataOnly: false,
          routeOnly: false
        },
        streamSettings: {
          sockopt: {
            tcpFastOpen: true,
            tcpNoDelay: true,
            tcpCongestion: "bbr",
            receiveBufferSize: 8388608,
            sendBufferSize: 8388608,
            mark: 255,
            tcpMaxSegSize: 1460
          }
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
            tcpFastOpen: true,
            tcpNoDelay: true,
            tcpCongestion: "bbr",
            tcpKeepAliveIdle: 600,
            tcpKeepAliveInterval: 30,
            tcpUserTimeout: 30000,
            tcpMaxSegSize: 1460,
            receiveBufferSize: 8388608,
            sendBufferSize: 8388608,
            mark: 255
          }
        },
        tag: "proxy"
      },
      {
        protocol: "freedom",
        settings: {
          domainStrategy: "UseIPv4",
          userLevel: 0
        },
        tag: "dns_out"
      },
      {
        protocol: "freedom",
        settings: {
          domainStrategy: "UseIPv4",
          userLevel: 0
        },
        tag: "direct"
      },
      {
        protocol: "blackhole",
        tag: "block"
      }
    ],
    policy: {
      levels: {
        "0": {
          uplinkOnly: 0,
          downlinkOnly: 0,
          statsUserUplink: false,
          statsUserDownlink: false,
          bufferSize: 65536,
          connIdle: 600,
          downConns: 1000,
          upConns: 1000
        }
      },
      system: {
        statsInbound: false,
        statsOutbound: false,
        statsUser: false
      }
    }
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
