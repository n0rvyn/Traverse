# Native package installation

Development builds are available from the successful [CI runs](https://github.com/n0rvyn/Traverse/actions/workflows/ci.yml). Choose the artifact for `x86_64` or `aarch64`; check `SHA256SUMS` before installation. No stable release has been published.

DEB packages use `apt install ./traverse_…deb`; RPM packages use `dnf install ./traverse-…rpm`. The current build baseline requires Linux with glibc2.35 or later. The package contains its own media libraries and does not replace the desktop's GStreamer installation. An existing X11 desktop and a trusted HTTPS certificate remain required.

Installation runs an encrypted synthetic-media check and creates a root-owned plugin registry. It starts no screen capture or network listener. A small system-libc helper receives only `CAP_NET_BIND_SERVICE`; it accepts only the installed service and TLS front end, preserves the desktop user's UID/GID, checks ownership/write permissions throughout the private runtime and rebuilds its environment from an allowlist. The TLS front end drops its capabilities before creating any worker threads. The media service retains only port-binding permission for ICE socket creation and rebinds. The helper grants no privilege to the adapter or desktop.

The package tests exercise these permissions under an unprivileged UID inside fresh containers, including a low-port negative control, real TLS connections and every live thread's capability sets. Container-only namespace and observer permissions used for these tests are not installation requirements or host configuration changes.

Portable archives do not carry file capabilities. A custom port1024 or above needs no binding helper; installing low-port permission requires an administrator-reviewed, root-owned installation. Do not run the desktop capture with `sudo` or change the host's global low-port policy.

Create your configuration from `/opt/traverse/share/traverse/config.example.json` and supply the domain, certificate and private-key paths. New `schemaVersion: 1` configurations default to443; `port` is editable, and `basePath` optionally places the client under a URL prefix. Run `traverse --config FILE --check-config`, then `traverse --config FILE` as the desktop owner. TLS paths can be absolute or relative to that new configuration file. Open the displayed URL in Chrome and use the local pairing code.

The standalone endpoint needs the chosen TCP and UDP port. TCP carries HTTPS and authenticated TURN/TLS fallback; direct WebRTC media uses UDP. Startup checks actual TCP/UDP binding availability and verifies local HTTPS trust and hostname before displaying readiness. It does not yet prove public reachability. A conflict fails without changing the existing service or choosing a different port. Integrated first-run host controls, external checks and certificate provisioning/renewal remain in development.

Existing configurations without `schemaVersion` retain their original HTTPS/media ports and legacy relative-path behavior. The separate `config.legacy.example.json` documents that format. Automatic Caddy or other reverse-proxy reconfiguration is not part of standalone launch.

Uninstall removes installed programs and the generated registry. User configuration and desktop data are retained. Existing Apex/Caddy or SSH listeners are never replaced automatically.
