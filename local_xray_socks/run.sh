#!/usr/bin/with-contenv bashio
set -euo pipefail
umask 077
source /supervise.sh
XRAY_PID=""
AWG_PID=""
trap cleanup_runtime EXIT
trap 'exit 0' TERM INT

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
    bashio::log.fatal "AmneziaWG profile ${AMNEZIAWG_PROFILE} is empty"
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
      interface:headerprotectionkey) AWG_HEADER_PROTECTION_KEY="${value}" ;;
      interface:contentpaddingaddition) AWG_CONTENT_PADDING_ADDITION="${value}" ;;
      interface:rekeyaftertime) AWG_REKEY_AFTER_TIME="${value}" ;;
      interface:rekeytimeout) AWG_REKEY_TIMEOUT="${value}" ;;
      interface:rejectaftertime) AWG_REJECT_AFTER_TIME="${value}" ;;
      interface:keepalivetimeout) AWG_KEEPALIVE_TIMEOUT="${value}" ;;
      interface:maxhandshakeattempts) AWG_MAX_HANDSHAKE_ATTEMPTS="${value}" ;;
      interface:randomtrailers) AWG_RANDOM_TRAILERS="${value}" ;;
      interface:disablecookies) AWG_DISABLE_COOKIES="${value}" ;;
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
  # Preserve an explicit zero (disabled), but keep NAT mappings alive by default.
  if [ -z "${AWG_KEEPALIVE}" ]; then
    AWG_KEEPALIVE="25"
  fi

  validate_amneziawg_31_config
  detect_amneziawg_config_version
}

validate_awg_bool() {
  local key="$1"
  local value="$2"

  case "${value,,}" in
    ""|on|off|0|1) ;;
    *)
      bashio::log.fatal "AmneziaWG option '${key}' must be on, off, 0, or 1"
      exit 1
      ;;
  esac
}

validate_amneziawg_31_config() {
  local padding

  validate_awg_bool "RandomTrailers" "${AWG_RANDOM_TRAILERS}"
  validate_awg_bool "DisableCookies" "${AWG_DISABLE_COOKIES}"

  if [ -n "${AWG_HEADER_PROTECTION_KEY}" ]; then
    for padding in "${AWG_S1}" "${AWG_S2}" "${AWG_S3}" "${AWG_S4}"; do
      if ! [[ "${padding}" =~ ^[0-9]+$ ]] || [ "${padding}" -lt 12 ]; then
        bashio::log.fatal "HeaderProtectionKey requires numeric S1-S4 values of at least 12"
        exit 1
      fi
    done
  fi
}

detect_amneziawg_config_version() {
  if [ -n "${AWG_RANDOM_TRAILERS}" ] || [ -n "${AWG_DISABLE_COOKIES}" ]; then
    AWG_CONFIG_VERSION="3.1"
    bashio::log.info "AmneziaWG protocol profile: 3.1 (RandomTrailers=${AWG_RANDOM_TRAILERS:-not set}, DisableCookies=${AWG_DISABLE_COOKIES:-not set})"
    return
  fi

  if [ -n "${AWG_HEADER_PROTECTION_KEY}" ] \
    || [ -n "${AWG_CONTENT_PADDING_ADDITION}" ] \
    || [ -n "${AWG_REKEY_AFTER_TIME}" ] \
    || [ -n "${AWG_REKEY_TIMEOUT}" ] \
    || [ -n "${AWG_REJECT_AFTER_TIME}" ] \
    || [ -n "${AWG_KEEPALIVE_TIMEOUT}" ] \
    || [ -n "${AWG_MAX_HANDSHAKE_ATTEMPTS}" ]; then
    AWG_CONFIG_VERSION="3.0"
    bashio::log.info "AmneziaWG protocol profile: 3.0 (AWG 3 parameters present, 3.1 parameters absent)"
    return
  fi

  AWG_CONFIG_VERSION="legacy"
  bashio::log.info "AmneziaWG protocol profile: legacy 1.x/2.x (no AWG 3.x parameters)"
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
  local engine_version

  if ip link show awg0 >/dev/null 2>&1; then
    ip link delete awg0 || true
  fi

  # The Home Assistant host may expose an older kernel module which can create
  # an interface but cannot apply AWG 3.1 parameters. Always use the versioned
  # userspace engine shipped in this image.
  engine_version="$(amneziawg-go --version 2>/dev/null | head -n 1 || true)"
  bashio::log.info "AmneziaWG engine: ${engine_version:-version unavailable}"
  bashio::log.info "Creating AmneziaWG userspace interface awg0 for protocol profile ${AWG_CONFIG_VERSION}"
  LOG_LEVEL="${LOGLEVEL}" amneziawg-go --foreground awg0 &
  AWG_PID=$!
}

log_amneziawg_state() {
  bashio::log.info "AmneziaWG interface state:"
  ip address show dev awg0 || true
  bashio::log.info "AmneziaWG peer state:"
  awg show awg0 || true
  bashio::log.info "IPv4 routes:"
  ip route show || true
  bashio::log.info "IPv4 AWG policy routes:"
  ip route show table 51820 || true
  bashio::log.info "IPv4 rules:"
  ip rule show || true
  bashio::log.info "IPv6 routes:"
  ip -6 route show || true
  bashio::log.info "IPv6 AWG policy routes:"
  ip -6 route show table 51820 || true
  bashio::log.info "IPv6 rules:"
  ip -6 rule show || true
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
  append_awg_option "HeaderProtectionKey" "${AWG_HEADER_PROTECTION_KEY}"
  append_awg_option "ContentPaddingAddition" "${AWG_CONTENT_PADDING_ADDITION}"
  append_awg_option "RekeyAfterTime" "${AWG_REKEY_AFTER_TIME}"
  append_awg_option "RekeyTimeout" "${AWG_REKEY_TIMEOUT}"
  append_awg_option "RejectAfterTime" "${AWG_REJECT_AFTER_TIME}"
  append_awg_option "KeepaliveTimeout" "${AWG_KEEPALIVE_TIMEOUT}"
  append_awg_option "MaxHandshakeAttempts" "${AWG_MAX_HANDSHAKE_ATTEMPTS}"
  append_awg_option "RandomTrailers" "${AWG_RANDOM_TRAILERS}"
  append_awg_option "DisableCookies" "${AWG_DISABLE_COOKIES}"

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
  local i address address_ip allowed_ip original_default original_gateway original_dev endpoint_ip

  parse_endpoint
  if [ -z "${AWG_ENDPOINT_HOST}" ] || [ -z "${AWG_ENDPOINT_PORT}" ] || [ "${AWG_ENDPOINT_HOST}" = "${AWG_ENDPOINT_PORT}" ]; then
    bashio::log.fatal "Option 'amneziawg_config' contains invalid Peer.Endpoint '${AWG_ENDPOINT}'"
    exit 1
  fi

  endpoint_ip="$(getent ahostsv4 "${AWG_ENDPOINT_HOST}" | awk '{ print $1; exit }' || true)"
  if [ -z "${endpoint_ip}" ]; then
    endpoint_ip="${AWG_ENDPOINT_HOST}"
  fi

  if [[ "${endpoint_ip}" == *:* ]]; then
    original_default="$(ip -6 route show default | head -n 1 || true)"
    AWG_ENDPOINT="[${endpoint_ip}]:${AWG_ENDPOINT_PORT}"
  else
    original_default="$(ip route show default | head -n 1 || true)"
    AWG_ENDPOINT="${endpoint_ip}:${AWG_ENDPOINT_PORT}"
  fi
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
    address_ip="${address%%/*}"
    if [[ "${address_ip}" == *:* ]]; then
      AWG_SEND_THROUGH_V6="${address_ip}"
    elif [ -z "${AWG_SEND_THROUGH}" ]; then
      AWG_SEND_THROUGH="${address_ip}"
    fi
  done < <(split_csv "${AWG_ADDRESS}")

  ip link set mtu "${AWG_MTU}" dev awg0
  ip link set up dev awg0

  route_endpoint_via_original_default "${endpoint_ip}" "${original_gateway}" "${original_dev}"

  while IFS= read -r allowed_ip; do
    [ -n "${allowed_ip}" ] || continue
    case "${allowed_ip}" in
      0.0.0.0/0) ip route replace default dev awg0 table 51820 ;;
      ::/0) ip -6 route replace default dev awg0 table 51820 || true ;;
      *) ip route replace "${allowed_ip}" dev awg0 table 51820 || ip -6 route replace "${allowed_ip}" dev awg0 table 51820 || true ;;
    esac
  done < <(split_csv "${AWG_ALLOWED_IPS}")

  if [ -n "${AWG_SEND_THROUGH}" ]; then
    ip rule add from "${AWG_SEND_THROUGH}" table 51820 priority 10000 2>/dev/null || true
  fi
  if [ -n "${AWG_SEND_THROUGH_V6}" ]; then
    ip -6 rule add from "${AWG_SEND_THROUGH_V6}" table 51820 priority 10000 2>/dev/null || true
  fi

  bashio::log.info "Started AmneziaWG target ${AWG_ENDPOINT_HOST}:${AWG_ENDPOINT_PORT} on awg0"
  wait_for_amneziawg_handshake
  log_amneziawg_state
}

write_socks_direct_xray_config() {
  mkdir -p /usr/local/etc/xray

  jq -n \
    --argjson socks_port "$SOCKS_PORT" \
    --arg loglevel "$LOGLEVEL" \
    --arg send_through "$AWG_SEND_THROUGH" \
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
        }
        + (if $send_through == "" then {} else {sendThrough: $send_through} end),
        {
          protocol: "blackhole",
          tag: "block"
        }
      ]
    }' > /usr/local/etc/xray/config.json
}

select_amneziawg_config() {
  case "${AMNEZIAWG_PROFILE}" in
    1) AMNEZIAWG_CONFIG="$(bashio::config 'amneziawg_config')" ;;
    2) AMNEZIAWG_CONFIG="$(bashio::config 'amneziawg_config_2')" ;;
    3) AMNEZIAWG_CONFIG="$(bashio::config 'amneziawg_config_3')" ;;
    4) AMNEZIAWG_CONFIG="$(bashio::config 'amneziawg_config_4')" ;;
    *)
      bashio::log.fatal "Option 'amneziawg_profile' must be 1, 2, 3, or 4"
      exit 1
      ;;
  esac

  bashio::log.info "Selected AmneziaWG profile ${AMNEZIAWG_PROFILE}"
}

LINK="$(bashio::config 'link')"
PROTOCOL="$(bashio::config 'protocol')"
AMNEZIAWG_PROFILE="$(bashio::config 'amneziawg_profile')"
AMNEZIAWG_CONFIG=""
LOGLEVEL="$(bashio::config 'loglevel')"
WATCHDOG_ENABLED="$(bashio::config 'watchdog_enabled')"
WATCHDOG_URLS="$(bashio::config 'watchdog_urls')"
if [ -z "${WATCHDOG_URLS}" ] || [ "${WATCHDOG_URLS}" = "null" ]; then
  WATCHDOG_URLS="https://www.cloudflare.com/cdn-cgi/trace,https://www.google.com/generate_204"
fi

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
AWG_HEADER_PROTECTION_KEY=""
AWG_CONTENT_PADDING_ADDITION=""
AWG_REKEY_AFTER_TIME=""
AWG_REKEY_TIMEOUT=""
AWG_REJECT_AFTER_TIME=""
AWG_KEEPALIVE_TIMEOUT=""
AWG_MAX_HANDSHAKE_ATTEMPTS=""
AWG_RANDOM_TRAILERS=""
AWG_DISABLE_COOKIES=""
AWG_CONFIG_VERSION="unknown"
AWG_PUBLIC_KEY=""
AWG_PRESHARED_KEY=""
AWG_ENDPOINT=""
AWG_ALLOWED_IPS=""
AWG_KEEPALIVE=""
AWG_ENDPOINT_HOST=""
AWG_ENDPOINT_PORT=""
AWG_SEND_THROUGH=""
AWG_SEND_THROUGH_V6=""

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
    select_amneziawg_config
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
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
/usr/local/bin/xray run -config /usr/local/etc/xray/config.json &
XRAY_PID=$!
supervise_runtime
bashio::log.warning "Restarting VPN processes in 30 seconds"
cleanup_runtime
sleep 30
exec /run.sh
