#!/usr/bin/env bash
# Run in the declared Ubuntu baseline container, never install build deps on a user's desktop.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=${TRAVERSE_BUILD_WORK:-"$root/.work"}
prefix="$work/runtime"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -c safe.directory="$root" -C "$root" log -1 --format=%ct)}
export DEBIAN_FRONTEND=noninteractive
if [[ -n ${SOURCE_COMMIT:-} && ! $SOURCE_COMMIT =~ ^[a-f0-9]{40}$ ]]; then echo "Invalid SOURCE_COMMIT" >&2; exit 1; fi
sed -n 's/^deb /deb-src /p' /etc/apt/sources.list > /etc/apt/sources.list.d/traverse-sources.list
apt-get update
apt-get install -y --no-install-recommends build-essential cmake ninja-build pkg-config python3 python3-venv python3-pip python3-gi dbus curl ca-certificates flex bison patch git \
  libglib2.0-dev libdbus-1-dev libssl-dev libvpx-dev libsrtp2-dev libusrsctp-dev libx11-dev libxext-dev libxfixes-dev libxdamage-dev libxtst-dev liborc-0.4-dev nlohmann-json3-dev \
  x11-utils xfonts-base xvfb xauth iproute2 dpkg-dev rpm patchelf libevent-dev libmicrohttpd-dev
apt-get install -y --no-install-recommends qt6-base-dev libgl-dev qt6-wayland
mkdir -p "$work/sources" "$prefix"
python3 -m venv "$work/tools"
"$work/tools/bin/pip" install meson==1.6.1 Jinja2==3.1.6
export PATH="$work/tools/bin:$PATH"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
export LD_LIBRARY_PATH="$prefix/lib"
python3 "$root/packaging/fetch-sources.py" "$work/sources"
# Extraction is verified and rejects traversal/symlinks before build.
common=(--prefix "$prefix" --libdir lib --buildtype release --wrap-mode nofallback -Dauto_features=disabled)
build_meson() {
  local name=$1; shift
  meson setup "$work/build-$name" "$work/sources/$name" "${common[@]}" "$@"
  meson compile -C "$work/build-$name" -j "${BUILD_JOBS:-2}"
  meson install -C "$work/build-$name"
}
build_meson gstreamer -Dtools=enabled
build_meson gst-plugins-base -Dapp=enabled -Dvideorate=enabled -Dvideoconvertscale=enabled -Dvideotestsrc=enabled -Dorc=enabled
patch --forward -p1 -d "$work/sources/libnice" < "$root/patches/libnice-0.1.24-passive-tcp-reuse.patch"
patch --forward --fuzz=0 -p1 -d "$work/sources/libnice" < "$root/patches/libnice-0.1.24-dns-gathering-completion.patch"
build_meson libnice -Dgstreamer=enabled -Dcrypto-library=openssl
build_meson gst-plugins-good -Dvpx=enabled -Drtp=enabled -Drtpmanager=enabled -Dximagesrc=enabled -Dximagesrc-xshm=enabled -Dximagesrc-xfixes=enabled -Dximagesrc-xdamage=enabled -Dorc=enabled
patch --forward -p1 -d "$work/sources/gst-plugins-bad" < "$root/patches/gstreamer-1.26.11-unixfd-socket-identity.patch"
patch --forward -p1 -d "$work/sources/gst-plugins-bad" < "$root/patches/gstreamer-1.26.11-unixfd-clock-offset.patch"
build_meson gst-plugins-bad -Dwebrtc=enabled -Dunixfd=enabled -Ddtls=enabled -Dsrtp=enabled -Dsctp=enabled -Dsctp-internal-usrsctp=disabled -Dorc=enabled
# Private EIS client; libeis is used only by native protocol checks. The package
# collects libraries reached from installed ELF consumers, excluding test tools.
patch --forward -p1 -d "$work/sources/libei" < "$root/patches/libei-1.5.0-setup-fd-ownership.patch"
patch --forward -p1 -d "$work/sources/libei" < "$root/patches/libei-1.5.0-pause-emulating-device.patch"
build_meson libei -Dlibei=enabled -Dlibeis=enabled -Dliboeffis=disabled -Dtests=disabled -Ddocumentation=[]
# Only client/plugin/module/config assets declared in the manifest are packaged.
# The user's PipeWire daemon and session manager remain distribution-owned.
patch --forward -p1 -d "$work/sources/pipewire" < "$root/patches/pipewire-1.6.0-unset-cycle-timestamp.patch"
patch --forward -p1 -d "$work/sources/pipewire" < "$root/patches/pipewire-1.6.0-pretransport-mix-cleanup.patch"
patch --forward -p1 -d "$work/sources/pipewire" < "$root/patches/pipewire-1.6.0-cancel-on-core-disconnect.patch"
build_meson pipewire -Dgstreamer=enabled -Dgstreamer-device-provider=disabled \
  -Dsession-managers=[] -Dpipewire-jack=disabled -Dpipewire-v4l2=disabled \
  -Dexamples=disabled -Dtests=disabled -Dinstalled_tests=disabled \
  -Dsystemd-system-service=disabled -Dsystemd-user-service=disabled \
  -Dsupport=enabled -Daudioconvert=enabled -Dvideoconvert=enabled \
  -Daudiomixer=disabled -Dcontrol=disabled -Daudiotestsrc=disabled -Dvideotestsrc=disabled -Dvolume=disabled
cmake -S "$work/sources/cpp-httplib" -B "$work/build-httplib" -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
  -DHTTPLIB_COMPILE=ON -DBUILD_SHARED_LIBS=ON -DHTTPLIB_REQUIRE_OPENSSL=ON -DHTTPLIB_USE_ZLIB_IF_AVAILABLE=OFF -DHTTPLIB_USE_BROTLI_IF_AVAILABLE=OFF -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF
cmake --build "$work/build-httplib" -j "${BUILD_JOBS:-2}"
cmake --install "$work/build-httplib"
cmake -S "$work/sources/coturn" -B "$work/build-coturn" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$prefix" -DWITH_MYSQL=OFF -DBUILD_TESTING=OFF
cmake --build "$work/build-coturn" --target turnserver -j "${BUILD_JOBS:-2}"
# The source archive retains examples/docs; only the server is part of our runtime.
install -m755 "$work/build-coturn/bin/turnserver" "$prefix/bin/turnserver"
# PyGObject is distribution-owned; the Meson-only venv deliberately has no system site packages.
cmake -S "$root/native" -B "$work/build-native" -G Ninja -DCMAKE_PREFIX_PATH="$prefix" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/traverse -DPython3_EXECUTABLE=/usr/bin/python3
cmake --build "$work/build-native" -j "${BUILD_JOBS:-2}"
# Actual route-event tests use only this owned dummy interface in the CI
# container's network namespace. Failure also removes the fixture interface.
test -f /.dockerenv
ip link add traverse-test0 type dummy
trap 'ip link del traverse-test0' EXIT
ip addr add 192.0.2.2/24 dev traverse-test0
ip link set traverse-test0 up
ctest --test-dir "$work/build-native" --output-on-failure
ip link del traverse-test0
trap - EXIT
DESTDIR="$work/stage" cmake --install "$work/build-native"
# Qt and its desktop plugins remain system-owned. Do not configure or run the
# UI with the private media loader/pkg-config environment above.
env -u LD_LIBRARY_PATH -u PKG_CONFIG_PATH -u PKG_CONFIG_LIBDIR -u CMAKE_PREFIX_PATH \
  cmake -S "$root/host" -B "$work/build-host" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/traverse -DBUILD_TESTING=ON
env -u LD_LIBRARY_PATH cmake --build "$work/build-host" -j "${BUILD_JOBS:-2}"
install -d -o nobody -g nogroup "$work/build-host/Testing"
runuser -u nobody -- env -u LD_LIBRARY_PATH ctest --test-dir "$work/build-host" --output-on-failure --no-tests=error
DESTDIR="$work/stage" env -u LD_LIBRARY_PATH cmake --install "$work/build-host"
runuser -u nobody -- env -u LD_LIBRARY_PATH \
  TRAVERSE_TEST_SYSTEM_UI_ELF="$work/stage/opt/traverse/libexec/traverse/traverse-host" \
  python3 -m unittest discover -s "$root/tests" -p test_packaging.py
runuser -u nobody -- env -u LD_LIBRARY_PATH \
  python3 -m unittest discover -s "$root/tests" -p test_artifact_payload.py
python3 "$root/packaging/build-issuer.py" --work "$work" --stage "$work/stage" --sources "$work/sources" --test-ca
python3 "$root/packaging/package.py" --stage "$work/stage" --runtime "$prefix" --sources "$work/sources" --issuer-build "$work/issuer-build.json" --output "$root/dist"
# Validate the exact assembled helper and frontend without contacting a public CA.
python3 "$root/tests/local_certificates_native.py" --probe "$work/build-native/certificate-manager-probe" --issuer "$work/stage/opt/traverse/libexec/traverse/traverse-issuer"
python3 "$root/tests/manager_native.py" --probe "$work/build-native/certificate-manager-probe" --issuer "$work/stage/opt/traverse/libexec/traverse/traverse-issuer" --pebble "$work/issuer-tools/pebble"
python3 "$root/tests/issuer_native.py" --prefix "$work/stage/opt/traverse" --issuer "$work/stage/opt/traverse/libexec/traverse/traverse-issuer" --pebble "$work/issuer-tools/pebble"
python3 "$root/tests/issuer_native.py" --prefix "$work/stage/opt/traverse" --issuer "$work/stage/opt/traverse/libexec/traverse/traverse-issuer" --pebble "$work/issuer-tools/pebble" --reuse-valid-authorizations
