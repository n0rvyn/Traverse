#!/bin/sh
set -eu
self=$(readlink -f -- "$0")
prefix=$(CDPATH= cd -- "$(dirname -- "$self")/.." && pwd)
export LD_LIBRARY_PATH="$prefix/lib"
export PATH="$prefix/libexec/traverse:$PATH"
export GST_PLUGIN_SYSTEM_PATH_1_0="$prefix/lib/gstreamer-1.0"
export GST_PLUGIN_PATH_1_0=
export GST_PLUGIN_SCANNER="$prefix/libexec/gstreamer-1.0/gst-plugin-scanner"
cache=${XDG_CACHE_HOME:-"$HOME/.cache"}/traverse
mkdir -p "$cache"
export GST_REGISTRY="$cache/registry-@VERSION@-$(uname -m).bin"
if [ -z "${SSL_CERT_FILE:-}" ]; then
  for certs in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
    if [ -r "$certs" ]; then export SSL_CERT_FILE="$certs"; break; fi
  done
fi
command=$(basename -- "$0")
if [ "$command" = traverse ]; then
  case "${1:-}" in
    --check-runtime) shift; exec "$prefix/libexec/traverse/traverse-runtime-check" "$@" ;;
    adapter) shift; command=traverse-adapter ;;
    service) shift; command=traverse-service ;;
    *) command=traverse-launcher ;;
  esac
fi
exec "$prefix/libexec/traverse/$command" "$@"
