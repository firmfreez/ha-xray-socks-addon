ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
FROM ${BUILD_FROM}

ARG BUILD_ARCH
ARG BUILD_VERSION

LABEL \
  io.hass.version="${BUILD_VERSION}" \
  io.hass.type="app" \
  io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache curl unzip jq

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