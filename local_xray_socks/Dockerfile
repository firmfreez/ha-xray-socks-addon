ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
# Private glibc loader for the pinned ARM64 Check Point binary. The established
# HA Alpine base and Xray/AmneziaWG toolchain remain unchanged.
FROM debian:trixie-slim AS checkpoint
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils libgcc-s1 \
    && curl -fL --retry 3 https://github.com/ancwrd1/snx-rs/releases/download/v6.4.1/snx-rs-v6.4.1-linux-arm64.tar.xz -o /tmp/snx.tar.xz \
    && echo '1e7fb8c3f528afe389fd3ae80e0a601b379bef6526e990eb1ea5203457d438ac  /tmp/snx.tar.xz' | sha256sum -c - \
    && tar -xJf /tmp/snx.tar.xz -C /tmp \
    && mkdir -p /bundle/lib \
    && cp /tmp/snx-rs-v6.4.1-linux-arm64/snx-rs /bundle/snx-rs \
    && cp /lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 /lib/aarch64-linux-gnu/libc.so.6 \
          /lib/aarch64-linux-gnu/libm.so.6 /lib/aarch64-linux-gnu/libgcc_s.so.1 /bundle/lib/ \
    && /bundle/snx-rs --version

FROM ${BUILD_FROM}

ARG BUILD_ARCH
ARG BUILD_VERSION

LABEL \
  io.hass.version="${BUILD_VERSION}" \
  io.hass.type="app" \
  io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache curl unzip jq bash iproute2 openresolv python3 openvpn openconnect vpnc socat iptables util-linux \
    && mkdir -p /run/vpnc \
    && test -x /etc/vpnc/vpnc-script

# Keep the engine and its userspace configuration tools on compatible AWG 3.1
# revisions. The tools project did not publish an AWG 3.1 tag yet, so pin the
# exact upstream commit instead of using a moving branch.
ARG AMNEZIAWG_GO_VERSION="v3.1.20260814"
ARG AMNEZIAWG_TOOLS_VERSION="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"

RUN apk add --no-cache --virtual .build-deps build-base go linux-headers make \
    && curl -L "https://github.com/amnezia-vpn/amneziawg-go/archive/${AMNEZIAWG_GO_VERSION}.tar.gz" -o /tmp/amneziawg-go.tar.gz \
    && mkdir -p /tmp/amneziawg-go \
    && tar -xzf /tmp/amneziawg-go.tar.gz -C /tmp/amneziawg-go --strip-components=1 \
    && make -C /tmp/amneziawg-go \
    && install -m 0755 /tmp/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go \
    && curl -L "https://github.com/amnezia-vpn/amneziawg-tools/archive/${AMNEZIAWG_TOOLS_VERSION}.tar.gz" -o /tmp/amneziawg-tools.tar.gz \
    && mkdir -p /tmp/amneziawg-tools \
    && tar -xzf /tmp/amneziawg-tools.tar.gz -C /tmp/amneziawg-tools --strip-components=1 \
    && make -C /tmp/amneziawg-tools/src WITH_WGQUICK=no \
    && make -C /tmp/amneziawg-tools/src WITH_WGQUICK=no install PREFIX=/usr \
    && apk del .build-deps \
    && rm -rf /tmp/amneziawg-go /tmp/amneziawg-go.tar.gz /tmp/amneziawg-tools /tmp/amneziawg-tools.tar.gz

ARG XRAY_ZIP_URL="https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip"

RUN curl -L "${XRAY_ZIP_URL}" -o /tmp/xray.zip \
    && unzip /tmp/xray.zip -d /tmp/xray \
    && install -m 0755 /tmp/xray/xray /usr/local/bin/xray \
    && mkdir -p /usr/local/etc/xray /usr/local/share/xray /var/log/xray \
    && if [ -f /tmp/xray/geoip.dat ]; then install -m 0644 /tmp/xray/geoip.dat /usr/local/share/xray/geoip.dat; fi \
    && if [ -f /tmp/xray/geosite.dat ]; then install -m 0644 /tmp/xray/geosite.dat /usr/local/share/xray/geosite.dat; fi \
    && rm -rf /tmp/xray /tmp/xray.zip

COPY run.sh /run.sh
COPY supervise.sh /supervise.sh
RUN chmod a+x /run.sh

COPY --from=checkpoint /bundle /opt/checkpoint
COPY snx-rs.sh /usr/local/bin/snx-rs
COPY manager /app
RUN python3 -c 'import os; from pathlib import Path; Path("/app/VERSION").write_text(os.environ.get("BUILD_VERSION") or "dev")'
RUN chmod 755 /usr/local/bin/snx-rs && snx-rs --version

CMD [ "/usr/bin/with-contenv", "python3", "/app/server.py" ]
