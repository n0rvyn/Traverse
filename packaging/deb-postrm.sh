#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
case "$1" in
  remove|purge) rm -f /opt/traverse/share/traverse/registry.bin ;;
esac
