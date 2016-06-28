#!/bin/bash

# This is for OpenVPN
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

exec "$@"
