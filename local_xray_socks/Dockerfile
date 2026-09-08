ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
FROM ${BUILD_FROM}

ARG BUILD_ARCH
ARG BUILD_VERSION

LABEL \
  io.hass.version="${BUILD_VERSION}" \
  io.hass.type="app" \
  io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache curl unzip jq bash iproute2 openresolv

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

ARG XRAY_ZIP_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip"

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

CMD [ "/run.sh" ]
