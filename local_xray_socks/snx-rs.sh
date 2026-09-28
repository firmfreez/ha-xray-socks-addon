#!/bin/sh
# Use the release's private glibc runtime without changing Alpine's system libc.
exec /opt/checkpoint/lib/ld-linux-aarch64.so.1 \
  --library-path /opt/checkpoint/lib /opt/checkpoint/snx-rs "$@"
