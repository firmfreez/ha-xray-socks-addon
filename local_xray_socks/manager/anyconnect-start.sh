#!/bin/sh
# Private resolver and vpnc bookkeeping per profile; routes are in its netns.
set -eu
work="$1"
shift
mount --bind "$work/transport-resolv.conf" /etc/resolv.conf
mkdir -p /var/run/vpnc
mount --bind "$work/vpnc" /var/run/vpnc
exec openconnect "$@" < "$work/password"
