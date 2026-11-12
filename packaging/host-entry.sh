#!/bin/sh
set -eu
# Keep the system Qt process outside the private media loader environment.
for option do
  case "$option" in
    --owner-fd|--owner-fd=*)
      printf '%s\n' 'The private host channel belongs to the native host process.' >&2
      exit 1 ;;
  esac
done
self=$(readlink -f -- "$0")
prefix=$(CDPATH= cd -- "$(dirname -- "$self")/.." && pwd)
unset LD_LIBRARY_PATH LD_PRELOAD TRAVERSE_RUNTIME_PREFIX
unset GST_PLUGIN_SYSTEM_PATH_1_0 GST_PLUGIN_PATH_1_0 GST_PLUGIN_SCANNER GST_REGISTRY
unset PIPEWIRE_MODULE_DIR SPA_PLUGIN_DIR PIPEWIRE_CONFIG_DIR PIPEWIRE_CONFIG_PREFIX PIPEWIRE_CONFIG_NAME
exec "$prefix/libexec/traverse/traverse-host" --prefix "$prefix" "$@"
