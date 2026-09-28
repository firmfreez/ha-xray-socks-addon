#!/bin/sh
# Run only inside this profile's network AND private mount namespaces.
set -eu
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net)" ]; then
    echo 'Check Point requires an isolated network namespace' >&2
    exit 1
fi
resolver=$1
config=$2
proc_mount="$(dirname "$resolver")/proc-net"
mkdir -p "$proc_mount"
# Docker masks /proc/sys read-only even with NET_ADMIN and SYS_ADMIN.
# Expose only network sysctls from a fresh proc mount; all other masks remain.
mount -t proc -o nosuid,nodev,noexec proc "$proc_mount"
trap 'umount "$proc_mount" 2>/dev/null || true; rmdir "$proc_mount" 2>/dev/null || true' EXIT
mount --bind "$proc_mount/sys/net" /proc/sys/net
umount "$proc_mount"
rmdir "$proc_mount"
trap - EXIT
mount --bind "$resolver" /etc/resolv.conf
exec snx-rs -c "$config"
