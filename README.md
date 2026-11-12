# Traverse

Native Linux desktop sharing in ordinary Chrome, built with C++17, GStreamer and WebRTC. No browser extension and no RDP/VNC wrapper.

**Status:** working existing-X11-session core with DEB/RPM/portable packages. Single-port setup, native host controls, automatic public-URL checks, native Wayland/GNOME/KDE verification and hardware-encoding optimization are active development work. No stable release has been published.

## How it works

An adapter captures an existing desktop and guards authorized input. A separate service handles HTTPS pairing/signaling, encoding and WebRTC. Chrome receives encrypted video and sends input over a data channel. A local one-use pairing code authorizes one controller; local Stop sharing revokes capture/input. An independent guardian releases remotely held keys/buttons when the adapter or service fails.

The runtime is native. Python is used only for development and test tooling. FD-backed pixel transport preserves the adapter/service boundary; it is not a blanket zero-copy claim.

## Packages and CI

Earlier CI verified DEB/RPM/portable builds and installation on x86_64 and arm64. The new native-host snapshot awaits its updated CI and desktop acceptance. See the [verified matrix](docs/compatibility.md) and [package build details](packaging/README.md). Branches: `dev` for daily work, `main` for reviewed milestones. No stable version tag has been published yet.

## Build from source

A Linux development environment needs CMake, a C++17 compiler, GLib/GIO, GStreamer WebRTC/SDP and libsrtp2 development libraries, X11/XTest, OpenSSL, cpp-httplib with TLS and nlohmann JSON. Required plugins include unixfd, ximagesrc, videoconvert, VP8, RTP, libnice, DTLS, SRTP and SCTP. The tested media version is GStreamer 1.26.11 and the tested cpp-httplib version is 0.51.0. Distribution development packages can be older; the private-runtime recipe builds the declared versions.

```sh
cmake -S native -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

Native tests also need the pinned PipeWire 1.6 client headers, libei/libeis 1.5 with the private repairs, libdbus development files, Python 3, PyGObject, Xvfb, `setxkbmap`, `xkbcomp` and `dbus-daemon`; the private-runtime build provides these. Internal Wayland tests exercise real GNOME/KDE permission grants, native frame transport, fresh-connection capture restart, revocation with a held received buffer, and standard portal pointer/button/scroll/keycode delivery. Native EIS sender checks use an actual private-bus grant and a native libeis peer for device readiness, monitor mapping, held-input cleanup, backpressure and revocation. Modern compositor acceptance is in progress. Installed Wayland control still needs EIS/guardian/Chrome integration and the complete host flow. GNOME native EIS input and held-input teardown passed; KDE normal input/Stop passed, but forced EIS-consumer death exposes a compositor pointer-frame defect retained in the evidence.

Review the [libnice reconnect patch](patches/README.md) when using a system libnice. The package build pins its runtime separately so it does not replace the host's media libraries.

## Run the package

The current package recipe adds the explicit `traverse-host` window for
hostname/port setup, local certificate export and Settings. See the
[native host build notes](host/README.md) for the separate Qt target. Run it as the desktop owner; it
uses system Qt6.2.4+ and remains under package/desktop acceptance. Local
certificates need no Internet connection: export the public CA certificate and
trust it once on each Chrome client. The existing CLI is available below.

Run as the desktop owner with a valid `DISPLAY`/`XAUTHORITY` and a private runtime directory. Create your configuration from `/opt/traverse/share/traverse/config.example.json`; set the self-hosted domain and trusted certificate/key paths. The versioned configuration defaults to443 and lets you choose another Chrome-compatible port:

```sh
traverse --check-runtime
traverse --config /path/to/config.json --check-config
traverse --config /path/to/config.json
```

Open the displayed URL in ordinary Chrome and enter the pairing code shown locally. The standalone launcher uses TCP on your chosen port for HTTPS and authenticated TURN/TLS fallback, plus UDP on the same port for direct media. Configure both protocols in the firewall/router. Local Stop sharing ends the owned sharing processes; ordinary browser disconnect still permits supported reconnect. See [installation and permissions](docs/install.md).

Existing configurations without `schemaVersion` retain their original HTTPS/media ports; `config.legacy.example.json` documents that format. A port conflict fails without replacing an existing service or selecting a different port. Portable archives have no binding capabilities and can use an editable high port. Native-package low-port support uses a constrained helper with the original desktop UID/GID.

A trusted certificate and a reachable network route are required. Startup verifies its own HTTPS endpoint and configured hostname; this local check does not prove public DNS, firewall or NAT reachability. Automatic external checks and integrated first-run host controls remain on the [roadmap](docs/roadmap.md). A page reload currently requires pairing again; local Stop sharing remains authoritative.

## Evidence and limits

On a two-core software-rendered test VM, two repeated visible-Chrome 1280×720 text/pointer workloads measured ~59.3 decoded fps, 1.01–1.06Mb/s video RTP payload and 74–94ms median input-to-decoded-frame response. These are short workload samples, not gaming/4K, GPU or physical input-to-photon benchmarks. Native process CPU was49–55% of host capacity, excluding the display server and desktop application.

Keyboard input follows the remote Linux layout. Physical Chrome key positions produced a/A on US and q/Q on French layouts in an actual WebRTC development-package test, including live layout switching and held-key release. This does not add client-character/IME translation or guarantee browser-reserved shortcuts.

Real X11 tests exercised typing/modifiers, scrolling, pointer mapping, application-window resize, reconnect, local revoke and crash handling. Direct UDP and a scoped authenticated TURN/TLS path were exercised. Private deployment traces are not published in this repository.

See [performance evidence](docs/performance.md) for later packaged-path measurements,
controlled packet-loss recovery checks and remaining relay variation.

This app attaches to an existing session; it does not create or unlock a desktop, authenticate a remote login, or currently provide a browser terminal. See [contribution/release policy](CONTRIBUTING.md) and [roadmap](docs/roadmap.md).
