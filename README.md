# Traverse

Native Linux desktop sharing in ordinary Chrome, built with C++17, GStreamer and WebRTC. No browser extension and no RDP/VNC wrapper.

**Status:** working existing-X11-session slice; installable-package and desktop compatibility work is in progress. Native Wayland/GNOME/KDE verification, automatic public-URL checks and hardware-encoding optimization are planned, not claimed complete.

## How it works

An adapter captures an existing desktop and guards authorized input. A separate service handles HTTPS pairing/signaling, encoding and WebRTC. Chrome receives encrypted video and sends input over a data channel. A local one-use pairing code authorizes one controller; local Stop sharing revokes capture/input. An independent guardian releases remotely held keys/buttons when the adapter or service fails.

The runtime is native. Python is used only for development and test tooling. FD-backed pixel transport preserves the adapter/service boundary; it is not a blanket zero-copy claim.

## Packages and CI

DEB/RPM/portable build automation and guarded tag releases are being verified. See [package build details](packaging/README.md). Branches: `dev` for daily work, `main` for reviewed milestones. No stable version tag has been published yet.

## Build from source

A Linux development environment needs CMake, a C++17 compiler, GStreamer WebRTC/SDP development libraries, X11/XTest, OpenSSL, cpp-httplib with TLS and nlohmann JSON. Required plugins include unixfd, ximagesrc, videoconvert, VP8, RTP, libnice, DTLS, SRTP and SCTP. The tested media version is GStreamer1.26.11.

```sh
cmake -S native -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

Review the [libnice reconnect patch](patches/README.md) when using a system libnice. The package build pins its runtime separately so it does not replace the host's media libraries.

## Run against an existing X11 desktop

Run as the desktop owner with a valid `DISPLAY`/`XAUTHORITY` and a private runtime directory:

```sh
build/traverse-adapter --display "$DISPLAY" --socket "$XDG_RUNTIME_DIR/traverse/adapter.sock"
build/traverse-service \
  --socket "$XDG_RUNTIME_DIR/traverse/adapter.sock" --web "$PWD/web" \
  --origin https://desktop.example.com:8443 \
  --cert /path/to/fullchain.pem --key /path/to/private-key.pem \
  --port 8443 --udp-port 50000
```

Open the URL in ordinary Chrome and enter the pairing code shown locally. The current low-level demo uses explicit HTTPS/media ports; the [roadmap](docs/roadmap.md) includes configurable default443 and proxy-aware setup. Do not set HTTPS and passive ICE-TCP to the same TCP port without a supported routing configuration.

A trusted certificate and a reachable network route are required. A standalone package cannot create a public domain or router forwarding by itself. A page reload currently requires pairing again; local Stop sharing remains authoritative.

## Evidence and limits

On a two-core software-rendered test VM, two repeated visible-Chrome 1280×720 text/pointer workloads measured ~59.3 decoded fps, 1.01–1.06Mb/s video RTP payload and 74–94ms median input-to-decoded-frame response. These are short workload samples, not gaming/4K, GPU or physical input-to-photon benchmarks. Native process CPU was49–55% of host capacity, excluding the display server and desktop application.

Real X11 tests exercised typing/modifiers, scrolling, pointer mapping, application-window resize, reconnect, local revoke and crash handling. Direct UDP and a scoped authenticated TURN/TLS path were exercised. Private deployment traces are not published in this repository.

This app attaches to an existing session; it does not create or unlock a desktop, authenticate a remote login, or currently provide a browser terminal. See [contribution/release policy](CONTRIBUTING.md) and [roadmap](docs/roadmap.md).
