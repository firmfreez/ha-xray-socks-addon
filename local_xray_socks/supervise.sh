#!/usr/bin/env bash

cleanup_runtime() {
  local pid i alive
  for pid in "${XRAY_PID:-}" "${AWG_PID:-}"; do
    [ -z "${pid}" ] || kill "${pid}" 2>/dev/null || true
  done
  for i in {1..5}; do
    alive=false
    for pid in "${XRAY_PID:-}" "${AWG_PID:-}"; do
      if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
        alive=true
      fi
    done
    if [ "${alive}" = false ]; then break; fi
    sleep 1
  done
  for pid in "${XRAY_PID:-}" "${AWG_PID:-}"; do
    if [ -n "${pid}" ]; then
      kill -KILL "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  XRAY_PID=""
  AWG_PID=""
  if [ "${PROTOCOL:-}" = amneziawg ]; then
    if [ -n "${AWG_SEND_THROUGH:-}" ]; then
      ip rule del from "${AWG_SEND_THROUGH}" table 51820 priority 10000 2>/dev/null || true
    fi
    if [ -n "${AWG_SEND_THROUGH_V6:-}" ]; then
      ip -6 rule del from "${AWG_SEND_THROUGH_V6}" table 51820 priority 10000 2>/dev/null || true
    fi
    ip link delete awg0 2>/dev/null || true
  fi
}

proxy_healthy() {
  local url
  while IFS= read -r url; do
    [ -n "${url}" ] || continue
    # Ignore proxy environment variables; DNS and the request must use SOCKS.
    # Any successful endpoint suffices, so one unavailable site cannot trigger recovery.
    if curl --silent --fail --output /dev/null --noproxy "" \
      --proxy "socks5h://127.0.0.1:${SOCKS_PORT}" \
      --connect-timeout 5 --max-time 10 --proto '=http,https' "${url}"; then
      return 0
    fi
  done < <(split_csv "${WATCHDOG_URLS}")
  return 1
}

supervise_runtime() {
  local failures=0 ticks=0
  while true; do
    sleep 5
    if ! kill -0 "${XRAY_PID}" 2>/dev/null; then
      bashio::log.warning "Xray process exited; recovery required"
      return
    fi
    if [ "${PROTOCOL}" = amneziawg ] && ! kill -0 "${AWG_PID}" 2>/dev/null; then
      bashio::log.warning "AmneziaWG process exited; recovery required"
      return
    fi
    if [ "${WATCHDOG_ENABLED}" = false ]; then
      continue
    fi
    ticks=$((ticks + 1))
    if [ "${ticks}" -lt 6 ]; then
      continue
    fi
    ticks=0
    if proxy_healthy; then
      if [ "${failures}" -gt 0 ]; then
        bashio::log.info "SOCKS connectivity recovered"
      fi
      failures=0
    else
      failures=$((failures + 1))
      bashio::log.warning "SOCKS connectivity check failed (${failures}/3)"
      if [ "${failures}" -ge 3 ]; then
        if [ "${PROTOCOL}" = amneziawg ]; then
          bashio::log.warning "AmneziaWG latest handshake and transfer counters:"
          timeout 3 awg show awg0 latest-handshakes || true
          timeout 3 awg show awg0 transfer || true
        fi
        return
      fi
    fi
  done
}
