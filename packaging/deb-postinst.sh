#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [ "$1" = configure ]; then
  /opt/traverse/libexec/traverse/configure-runtime
  setcap cap_net_bind_service=ep /opt/traverse/libexec/traverse/traverse-bind-helper
fi
