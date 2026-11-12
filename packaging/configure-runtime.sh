#!/bin/sh
# Native-package configuration only: synthetic media, no display or listener.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
test "$(id -u)" = 0
prefix=/opt/traverse
registry=$(mktemp "$prefix/share/traverse/.registry.XXXXXX")
trap 'rm -f "$registry"' EXIT HUP INT TERM
env -i PATH=/usr/bin:/bin HOME=/root LANG=C.UTF-8 \
  TRAVERSE_RUNTIME_PREFIX="$prefix" LD_LIBRARY_PATH="$prefix/lib" \
  GST_PLUGIN_SYSTEM_PATH="$prefix/lib/gstreamer-1.0" \
  GST_PLUGIN_SYSTEM_PATH_1_0="$prefix/lib/gstreamer-1.0" \
  GST_PLUGIN_PATH= GST_PLUGIN_PATH_1_0= \
  GST_PLUGIN_SCANNER="$prefix/libexec/gstreamer-1.0/gst-plugin-scanner" \
  GST_PLUGIN_SCANNER_1_0="$prefix/libexec/gstreamer-1.0/gst-plugin-scanner" \
  PIPEWIRE_MODULE_DIR="$prefix/lib/pipewire-0.3" SPA_PLUGIN_DIR="$prefix/lib/spa-0.2" \
  PIPEWIRE_CONFIG_DIR="$prefix/share/pipewire" PIPEWIRE_CONFIG_PREFIX= PIPEWIRE_CONFIG_NAME=client.conf \
  GST_REGISTRY="$registry" GST_REGISTRY_1_0="$registry" \
  "$prefix/libexec/traverse/traverse-runtime-check"
test -s "$registry"
chmod 0644 "$registry"
mv -f "$registry" "$prefix/share/traverse/registry.bin"
trap - EXIT HUP INT TERM
