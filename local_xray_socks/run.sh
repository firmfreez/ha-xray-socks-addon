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

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

split_csv() {
  local value="$1"
  local item
  IFS=',' read -r -a CSV_ITEMS <<< "${value}"
  for item in "${CSV_ITEMS[@]}"; do
    trim "${item}"
    printf '\n'
  done
}

parse_amneziawg_config() {
  local config="$1"
  local parsed_file key value section received_preview

  if [[ "${config}" != *"[Interface]"* && "${LINK}" == *"[Interface]"* ]]; then
    config="${LINK}"
  fi

  if [ -z "${config}" ]; then
    bashio::log.fatal "Option 'amneziawg_config' is required when protocol=amneziawg"
    exit 1
  fi

  if [[ "${config}" == vpn://* ]] || [[ "${LINK}" == vpn://* ]]; then
    bashio::log.fatal "Amnezia vpn:// links are not supported yet. Paste the full [Interface]/[Peer] config into 'amneziawg_config'"
    exit 1
  fi

  if [[ "${config}" != *$'\n'* && "${config}" == *'\\n'* ]]; then
    config="$(printf '%b' "${config}")"
  fi

  if [[ "${config}" != *"[Interface]"* && "${LINK}" == *'\\n'* ]]; then
    LINK="$(printf '%b' "${LINK}")"
    if [[ "${LINK}" == *"[Interface]"* ]]; then
      config="${LINK}"
    fi
  fi

  mkdir -p /tmp/amneziawg
  printf '%s\n' "${config}" | awk '
    /^\047?[[:space:]]*\[Interface\][[:space:]]*\047?$/ { found=1 }
    found {
      gsub(/^\047|^\042|\047$|\042$/, "")
      print
    }
  ' > /tmp/amneziawg/client.conf

  if [ ! -s /tmp/amneziawg/client.conf ]; then
    printf '%s\n' "${config}" > /tmp/amneziawg/client.conf
  fi

  parsed_file="/tmp/amneziawg/parsed.tsv"

  awk '
    function trim(s) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
      return s
    }
    {
      sub(/\r$/, "")
      if ($0 ~ /^[[:space:]]*($|#|;)/) next
      if ($0 ~ /^[[:space:]]*\[/) {
        section=tolower($0)
        gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
        next
      }
      pos=index($0, "=")
      if (pos == 0) next
      key=tolower(trim(substr($0, 1, pos - 1)))
      value=trim(substr($0, pos + 1))
      print section "\t" key "\t" value
    }
  ' /tmp/amneziawg/client.conf > "${parsed_file}"

  while IFS=$'\t' read -r section key value; do
    case "${section}:${key}" in
      interface:privatekey) AWG_PRIVATE_KEY="${value}" ;;
      interface:address) AWG_ADDRESS="${value}" ;;
      interface:mtu) AWG_MTU="${value}" ;;
      interface:listenport) AWG_LISTEN_PORT="${value}" ;;
      interface:jc) AWG_JC="${value}" ;;
      interface:jmin) AWG_JMIN="${value}" ;;
      interface:jmax) AWG_JMAX="${value}" ;;
      interface:s1) AWG_S1="${value}" ;;
      interface:s2) AWG_S2="${value}" ;;
      interface:s3) AWG_S3="${value}" ;;
      interface:s4) AWG_S4="${value}" ;;
      interface:h1) AWG_H1="${value}" ;;
      interface:h2) AWG_H2="${value}" ;;
      interface:h3) AWG_H3="${value}" ;;
      interface:h4) AWG_H4="${value}" ;;
      interface:i1) AWG_I1="${value}" ;;
      interface:i2) AWG_I2="${value}" ;;
      interface:i3) AWG_I3="${value}" ;;
      interface:i4) AWG_I4="${value}" ;;
      interface:i5) AWG_I5="${value}" ;;
      peer:publickey) AWG_PUBLIC_KEY="${value}" ;;
      peer:presharedkey) AWG_PRESHARED_KEY="${value}" ;;
      peer:endpoint) AWG_ENDPOINT="${value}" ;;
      peer:allowedips) AWG_ALLOWED_IPS="${value}" ;;
      peer:persistentkeepalive) AWG_KEEPALIVE="${value}" ;;
    esac
  done < "${parsed_file}"

  if [ -z "${AWG_PRIVATE_KEY}" ]; then
    received_preview="$(awk '
      BEGIN { count=0 }
      count < 8 {
        line=$0
        pos=index(line, "=")
        if (pos > 0) {
          key=substr(line, 1, pos - 1)
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
          print key " = ..."
        } else if (length(line) > 0) {
          print line
        }
        count++
      }
    ' /tmp/amneziawg/client.conf | tr "\n" " " | cut -c1-240)"
    bashio::log.warning "Received AmneziaWG config preview: ${received_preview}"
    bashio::log.fatal "Option 'amneziawg_config' does not contain Interface.PrivateKey"
    exit 1
  fi
  if [ -z "${AWG_ADDRESS}" ]; then
    bashio::log.fatal "Option 'amneziawg_config' does not contain Interface.Address"
    exit 1
  fi
  if [ -z "${AWG_PUBLIC_KEY}" ]; then
    bashio::log.fatal "Option 'amneziawg_config' does not contain Peer.PublicKey"
    exit 1
  fi
  if [ -z "${AWG_ENDPOINT}" ]; then
    bashio::log.fatal "Option 'amneziawg_config' does not contain Peer.Endpoint"
    exit 1
  fi
  if [ -z "${AWG_ALLOWED_IPS}" ]; then
    AWG_ALLOWED_IPS="0.0.0.0/0, ::/0"
  fi
  if [ -z "${AWG_MTU}" ]; then
    AWG_MTU="1280"
  fi
}

append_awg_option() {
  local key="$1"
  local value="$2"

  if [ -n "${value}" ]; then
    printf '%s = %s\n' "${key}" "${value}" >> /tmp/amneziawg/awg0.conf
  fi
}

route_endpoint_via_original_default() {
  local endpoint_ip="$1"
  local original_gateway="$2"
  local original_dev="$3"
  local route_target route_cmd

  if [[ "${endpoint_ip}" == *:* ]]; then
    route_target="${endpoint_ip}/128"
    route_cmd=(ip -6 route replace "${route_target}")
  else
    route_target="${endpoint_ip}/32"
    route_cmd=(ip route replace "${route_target}")
  fi

  if [ -n "${original_gateway}" ]; then
    route_cmd+=(via "${original_gateway}")
  fi
  if [ -n "${original_dev}" ]; then
    route_cmd+=(dev "${original_dev}")
  fi

  if [ -n "${original_gateway}" ] || [ -n "${original_dev}" ]; then
    "${route_cmd[@]}"
  fi
}

create_amneziawg_interface() {
  if ip link show awg0 >/dev/null 2>&1; then
    ip link delete awg0 || true
  fi

  if ip link add dev awg0 type amneziawg >/tmp/amneziawg/ip-link-add.log 2>&1; then
    bashio::log.info "Created native AmneziaWG kernel interface awg0"
    return
  fi

  bashio::log.info "Native AmneziaWG interface is unavailable, falling back to amneziawg-go"
  amneziawg-go awg0
}

log_amneziawg_state() {
  bashio::log.info "AmneziaWG interface state:"
  ip address show dev awg0 || true
  bashio::log.info "AmneziaWG peer state:"
  awg show awg0 || true
  bashio::log.info "IPv4 routes:"
  ip route show || true
  bashio::log.info "IPv6 routes:"
  ip -6 route show || true
}

wait_for_amneziawg_handshake() {
  local i latest_handshake transfer_line

  for i in $(seq 1 20); do
    latest_handshake="$(awg show awg0 latest-handshakes 2>/dev/null | awk '{ print $2; exit }' || true)"
    if [ -n "${latest_handshake}" ] && [ "${latest_handshake}" != "0" ]; then
      bashio::log.info "AmneziaWG handshake established"
      return
    fi
    sleep 1
  done

  transfer_line="$(awg show awg0 transfer 2>/dev/null | awk '{ print "received=" $2 ", sent=" $3; exit }' || true)"
  bashio::log.warning "AmneziaWG handshake was not established after 20 seconds (${transfer_line:-no transfer stats})"
  bashio::log.warning "Check that the endpoint UDP port is reachable and that PrivateKey/PublicKey/PresharedKey/AmneziaWG parameters match the server"
}

write_amneziawg_interface_config() {
  {
    printf '[Interface]\n'
    printf 'PrivateKey = %s\n' "${AWG_PRIVATE_KEY}"
  } > /tmp/amneziawg/awg0.conf

  append_awg_option "ListenPort" "${AWG_LISTEN_PORT}"
  append_awg_option "Jc" "${AWG_JC}"
  append_awg_option "Jmin" "${AWG_JMIN}"
  append_awg_option "Jmax" "${AWG_JMAX}"
  append_awg_option "S1" "${AWG_S1}"
  append_awg_option "S2" "${AWG_S2}"
  append_awg_option "S3" "${AWG_S3}"
  append_awg_option "S4" "${AWG_S4}"
  append_awg_option "H1" "${AWG_H1}"
  append_awg_option "H2" "${AWG_H2}"
  append_awg_option "H3" "${AWG_H3}"
  append_awg_option "H4" "${AWG_H4}"
  append_awg_option "I1" "${AWG_I1}"
  append_awg_option "I2" "${AWG_I2}"
  append_awg_option "I3" "${AWG_I3}"
  append_awg_option "I4" "${AWG_I4}"
  append_awg_option "I5" "${AWG_I5}"

  {
    printf '\n[Peer]\n'
    printf 'PublicKey = %s\n' "${AWG_PUBLIC_KEY}"
    append_awg_option "PresharedKey" "${AWG_PRESHARED_KEY}"
    printf 'Endpoint = %s\n' "${AWG_ENDPOINT}"
    printf 'AllowedIPs = %s\n' "${AWG_ALLOWED_IPS}"
    append_awg_option "PersistentKeepalive" "${AWG_KEEPALIVE}"
  } >> /tmp/amneziawg/awg0.conf
}

parse_endpoint() {
  if [[ "${AWG_ENDPOINT}" == \[*\]:* ]]; then
    AWG_ENDPOINT_HOST="${AWG_ENDPOINT%%]*}"
    AWG_ENDPOINT_HOST="${AWG_ENDPOINT_HOST#[}"
    AWG_ENDPOINT_PORT="${AWG_ENDPOINT##*:}"
    return
  fi

  AWG_ENDPOINT_HOST="${AWG_ENDPOINT%:*}"
  AWG_ENDPOINT_PORT="${AWG_ENDPOINT##*:}"
}

setup_amneziawg() {
  local i address allowed_ip original_default original_gateway original_dev endpoint_ip

  parse_endpoint
  if [ -z "${AWG_ENDPOINT_HOST}" ] || [ -z "${AWG_ENDPOINT_PORT}" ] || [ "${AWG_ENDPOINT_HOST}" = "${AWG_ENDPOINT_PORT}" ]; then
    bashio::log.fatal "Option 'amneziawg_config' contains invalid Peer.Endpoint '${AWG_ENDPOINT}'"
    exit 1
  fi

  endpoint_ip="$(getent ahostsv4 "${AWG_ENDPOINT_HOST}" | awk '{ print $1; exit }' || true)"
  if [ -z "${endpoint_ip}" ]; then
    endpoint_ip="${AWG_ENDPOINT_HOST}"
  fi

  original_default="$(ip route show default | head -n 1 || true)"
  original_gateway="$(awk '{ for (i=1; i<=NF; i++) if ($i == "via") print $(i+1) }' <<< "${original_default}")"
  original_dev="$(awk '{ for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1) }' <<< "${original_default}")"

  write_amneziawg_interface_config
  create_amneziawg_interface

  for i in $(seq 1 20); do
    if ip link show awg0 >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done

  if ! ip link show awg0 >/dev/null 2>&1; then
    bashio::log.fatal "Failed to create AmneziaWG interface awg0"
    exit 1
  fi

  awg setconf awg0 /tmp/amneziawg/awg0.conf

  while IFS= read -r address; do
    [ -n "${address}" ] || continue
    ip address add "${address}" dev awg0
  done < <(split_csv "${AWG_ADDRESS}")

  ip link set mtu "${AWG_MTU}" dev awg0
  ip link set up dev awg0

  route_endpoint_via_original_default "${endpoint_ip}" "${original_gateway}" "${original_dev}"

  while IFS= read -r allowed_ip; do
    [ -n "${allowed_ip}" ] || continue
    case "${allowed_ip}" in
      0.0.0.0/0) ip route replace default dev awg0 ;;
      ::/0) ip -6 route replace default dev awg0 || true ;;
      *) ip route replace "${allowed_ip}" dev awg0 || ip -6 route replace "${allowed_ip}" dev awg0 || true ;;
    esac
  done < <(split_csv "${AWG_ALLOWED_IPS}")

  bashio::log.info "Started AmneziaWG target ${AWG_ENDPOINT_HOST}:${AWG_ENDPOINT_PORT} on awg0"
  wait_for_amneziawg_handshake
  log_amneziawg_state
}

write_socks_direct_xray_config() {
  mkdir -p /usr/local/etc/xray

  jq -n \
    --argjson socks_port "$SOCKS_PORT" \
    --arg loglevel "$LOGLEVEL" \
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
          protocol: "freedom",
          tag: "proxy"
        },
        {
          protocol: "blackhole",
          tag: "block"
        }
      ]
    }' > /usr/local/etc/xray/config.json
}

LINK="$(bashio::config 'link')"
PROTOCOL="$(bashio::config 'protocol')"
AMNEZIAWG_CONFIG="$(bashio::config 'amneziawg_config')"
LOGLEVEL="$(bashio::config 'loglevel')"

SOCKS_PORT="1080"
SERVER=""
PORT=""
UUID=""
SNI=""
FLOW=""
FINGERPRINT=""
ALPN=""
AWG_PRIVATE_KEY=""
AWG_ADDRESS=""
AWG_MTU=""
AWG_LISTEN_PORT=""
AWG_JC=""
AWG_JMIN=""
AWG_JMAX=""
AWG_S1=""
AWG_S2=""
AWG_S3=""
AWG_S4=""
AWG_H1=""
AWG_H2=""
AWG_H3=""
AWG_H4=""
AWG_I1=""
AWG_I2=""
AWG_I3=""
AWG_I4=""
AWG_I5=""
AWG_PUBLIC_KEY=""
AWG_PRESHARED_KEY=""
AWG_ENDPOINT=""
AWG_ALLOWED_IPS=""
AWG_KEEPALIVE=""
AWG_ENDPOINT_HOST=""
AWG_ENDPOINT_PORT=""

case "${PROTOCOL}" in
  vless)
    if [ -z "${LINK}" ]; then
      bashio::log.fatal "Option 'link' is required when protocol=vless"
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
    ;;
  amneziawg)
    parse_amneziawg_config "${AMNEZIAWG_CONFIG}"
    setup_amneziawg
    write_socks_direct_xray_config
    ;;
  *)
    bashio::log.fatal "Unsupported protocol '${PROTOCOL}'"
    exit 1
    ;;
esac

bashio::log.info "Starting Xray on SOCKS5 port ${SOCKS_PORT}"
if [ "${LOGLEVEL}" = "debug" ]; then
  bashio::log.info "Generated Xray config:"
  cat /usr/local/etc/xray/config.json
fi
exec /usr/local/bin/xray run -config /usr/local/etc/xray/config.json
