ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
FROM ${BUILD_FROM}

ARG BUILD_ARCH
ARG BUILD_VERSION

LABEL \
  io.hass.version="${BUILD_VERSION}" \
  io.hass.type="app" \
  io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache curl unzip jq bash iproute2 openresolv

ARG AMNEZIAWG_GO_VERSION="master"
ARG AMNEZIAWG_TOOLS_VERSION="v1.0.20260223"

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
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
