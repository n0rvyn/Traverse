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
apt-get install -y --no-install-recommends build-essential cmake ninja-build pkg-config python3 python3-venv python3-pip curl ca-certificates flex bison patch git \
  libglib2.0-dev libssl-dev libvpx-dev libsrtp2-dev libusrsctp-dev libx11-dev libxext-dev libxfixes-dev libxdamage-dev libxtst-dev liborc-0.4-dev nlohmann-json3-dev \
  x11-utils xfonts-base xvfb xauth dpkg-dev rpm patchelf
mkdir -p "$work/sources" "$prefix"
python3 -m venv "$work/tools"
"$work/tools/bin/pip" install meson==1.6.1
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
build_meson gst-plugins-base -Dapp=enabled -Dvideoconvertscale=enabled -Dvideotestsrc=enabled -Dorc=enabled
patch --forward -p1 -d "$work/sources/libnice" < "$root/patches/libnice-0.1.24-passive-tcp-reuse.patch"
build_meson libnice -Dgstreamer=enabled -Dcrypto-library=openssl
build_meson gst-plugins-good -Dvpx=enabled -Drtp=enabled -Drtpmanager=enabled -Dximagesrc=enabled -Dximagesrc-xshm=enabled -Dximagesrc-xfixes=enabled -Dximagesrc-xdamage=enabled -Dorc=enabled
build_meson gst-plugins-bad -Dwebrtc=enabled -Dunixfd=enabled -Ddtls=enabled -Dsrtp=enabled -Dsctp=enabled -Dsctp-internal-usrsctp=disabled -Dorc=enabled
cmake -S "$work/sources/cpp-httplib" -B "$work/build-httplib" -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
  -DHTTPLIB_COMPILE=ON -DBUILD_SHARED_LIBS=ON -DHTTPLIB_REQUIRE_OPENSSL=ON -DHTTPLIB_USE_ZLIB_IF_AVAILABLE=OFF -DHTTPLIB_USE_BROTLI_IF_AVAILABLE=OFF -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF
cmake --build "$work/build-httplib" -j "${BUILD_JOBS:-2}"
cmake --install "$work/build-httplib"
cmake -S "$root/native" -B "$work/build-native" -G Ninja -DCMAKE_PREFIX_PATH="$prefix" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/traverse
cmake --build "$work/build-native" -j "${BUILD_JOBS:-2}"
DESTDIR="$work/stage" cmake --install "$work/build-native"
python3 "$root/packaging/package.py" --stage "$work/stage" --runtime "$prefix" --sources "$work/sources" --output "$root/dist"
