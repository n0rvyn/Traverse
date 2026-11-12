# Native package installation

Development builds are available from the successful [CI runs](https://github.com/n0rvyn/Traverse/actions/workflows/ci.yml). Choose the artifact for `x86_64` or `aarch64`; check `SHA256SUMS` before installation. No stable release has been published.

The [verified development build](https://github.com/n0rvyn/Traverse/actions/runs/43306397479) includes the native `traverse-host` entry on x86_64 and arm64. It uses system Qt6.2.4+ and OpenSSL3; no Python, compiler or Go installation is needed to run it. Installed DEB/RPM and portable lifecycle checks passed on both architectures. The complete ordinary Chrome journey passed on isolated x86_64 X11 displays in Ubuntu and Gentoo userlands, including Gentoo system Qt6.11.3 and Chrome157. Normal GNOME/KDE Wayland integration and physical-hardware latency remain open.

## Install and start sharing

Download the artifact matching your CPU architecture from that successful run, extract its ZIP, and verify `sha256sum -c SHA256SUMS`. Install the native package so the package manager resolves its system UI dependencies:

```sh
# Debian/Ubuntu x86_64; arm64 uses traverse_0.1.0_arm64.deb
sudo apt install ./traverse_0.1.0_amd64.deb

# Fedora x86_64; ARM64 uses traverse-0.1.0-1.aarch64.rpm
sudo dnf install ./traverse-0.1.0-1.x86_64.rpm
```

Run `traverse-host` as the owner of the existing X11 desktop. On first launch:

1. Enter the hostname/address Chrome will use. Keep port443 or enter your own unused Chrome-compatible port. A conflict is reported without changing the existing service.
2. Keep locally generated certificates selected, or choose existing certificates, then click Start sharing.
3. Once local HTTPS is ready, use Export CA certificate. Trust only that public certificate once on each Chrome client; the private CA key remains on Linux. The app does not install client trust for you. Supplied certificates already trusted by Chrome do not need this export step.
4. Open the displayed Remote URL in Chrome and enter the pairing code shown on Linux. Stop sharing, or closing the host window, ends sharing.

Settings saves domain, port and certificate changes for the next launch. It shows “Saved. Changes take effect the next time you launch Traverse.” Sharing continues on the active settings until stopped.

Local certificate generation works without Internet access. The hostname still needs to resolve to the host from the client, and the selected TCP/UDP port needs a working network route. Local HTTPS readiness does not prove public reachability.

## Runtime and advanced configuration

The current build baseline requires Linux with glibc2.35 or later. The package contains its own media libraries and does not replace the desktop's GStreamer installation. An existing X11 desktop remains required. HTTPS supports locally generated certificates, supplied trusted material or explicitly configured automatic enrollment.

Installation runs an encrypted synthetic-media check and creates a root-owned plugin registry. It starts no screen capture or network listener. A small system-libc helper receives only `CAP_NET_BIND_SERVICE`; it accepts only the installed service and TLS front end, preserves the desktop user's UID/GID, checks ownership/write permissions throughout the private runtime and rebuilds its environment from an allowlist. The TLS front end drops its capabilities before creating any worker threads. The media service retains only port-binding permission for ICE socket creation and rebinds. The helper grants no privilege to the adapter or desktop.

The package tests exercise these permissions under an unprivileged UID inside fresh containers, including a low-port negative control, real TLS connections and every live thread's capability sets. Container-only namespace and observer permissions used for these tests are not installation requirements or host configuration changes.

Portable archives do not carry file capabilities. Supplied-certificate mode on a custom port1024 or above needs no binding helper. Automatic mode still needs permission for standard validation TCP443, including with a custom application port; installing low-port permission requires an administrator-reviewed, root-owned installation. Do not run the desktop capture with `sudo` or change the host's global low-port policy.

Create your configuration from `/opt/traverse/share/traverse/config.example.json` and supply the domain, certificate and private-key paths. New `schemaVersion: 1` configurations default to443; `port` is editable, and `basePath` optionally places the client under a URL prefix. Run `traverse --config FILE --check-config`, then `traverse --config FILE` as the desktop owner. TLS paths can be absolute or relative to that new configuration file. Open the displayed URL in Chrome and use the local pairing code.

The standalone endpoint needs the chosen TCP and UDP port. TCP carries HTTPS and authenticated TURN/TLS fallback; direct WebRTC media uses UDP. Startup checks actual TCP/UDP binding availability and verifies local HTTPS trust and hostname before displaying readiness. It does not yet prove public reachability. A conflict fails without changing the existing service or choosing a different port. Native host controls passed the installed synthetic-X11 paths described above; external-check notifications remain in development.

The supplied-certificate commands above remain available. The separate automatic
backend requires an explicit CA directory and exact local terms approval; no
public CA provider or terms acceptance is inferred from installation. Public CA
validation still uses standard ports, regardless of the application port.

The packaged certificate issuer is a separate executable and needs no Go installation. Installing it does not accept CA terms, create an account, request a certificate or start sharing. The native supervisor owns automatic bootstrap and renewal while sharing runs; automatic-provider consent presentation remains in development.

Versioned configurations can select the internal automatic backend with a `certificateSettings` object instead of top-level `certificate`/`privateKey` paths. Its fields are `mode: "automatic"`, the HTTPS ACME `directory`, the exact approved `termsURL` and boolean `termsAgreed`; optional absolute `apiTrustFile` and `certificateTrustFile` select per-instance trust. An empty terms reference is valid only for a CA that advertises no terms. Review the CA's current terms before recording approval. The package supplies no provider default and never records that approval on the owner's behalf.

Automatic TLS-ALPN validation requires the domain's public TCP443 route. All required local listeners must be available before an account or order starts. A custom app port keeps its URL and uses a separate validation-only443 listener, which rejects ordinary HTTPS and TURN. An existing443 service is never replaced. If cached material is still valid, a custom app endpoint can keep sharing while its unavailable renewal route needs attention.

Managed account keys, bundles and fingerprint-bound renewal timing persist in the owner's private XDG data directory. Valid cached material is reused on startup; renewal uses validated CA timing or the certificate's actual lifetime. Publication is checked against actual frontend admission. Changed terms and ambiguous interrupted orders require attention rather than silent acceptance or a blind new order. Stop and parent death end owned issuer/listener work; certificate renewal preserves the controller and established TLS sessions. Existing supplied configurations retain their paths and behavior.

The certificate and key must remain readable by the desktop user after binding privileges are dropped, including after replacements. A different service’s protected certificate directory is not automatically shared with Traverse.

Versioned standalone configurations watch their certificate and key files. An external certificate manager can replace those files without restarting sharing. A replacement must have a matching key, a valid server chain and validity period, and the configured domain or IP in its Subject Alternative Name. New connections use the validated replacement; established HTTPS/TURN connections and desktop/input processes continue running.

An invalid or incomplete replacement leaves the previous valid certificate active and reports the rejection. Once that certificate expires, new TLS connections are refused, including handshakes that began before expiry. Already established TLS connections remain usable until normal disconnect or local Stop sharing. Restoring valid files recovers admission automatically. This reload support does not enroll with a certificate authority or schedule issuance itself.

Existing `SSL_CERT_FILE` and `SSL_CERT_DIR` trust selections are carried explicitly through low-port launch. Relative trust locations refer to the caller's working directory; certificate/key paths in a versioned configuration still refer to the configuration file's directory. The binding helper keeps its restricted environment. A private CA must also be trusted by the Chrome client; trusting it only on the Linux host does not establish browser trust.

Existing configurations without `schemaVersion` retain their original HTTPS/media ports and legacy relative-path behavior. The separate `config.legacy.example.json` documents that format. Automatic Caddy or other reverse-proxy reconfiguration is not part of standalone launch.

Uninstall removes installed programs and the generated registry. User configuration and desktop data are retained. Existing Apex/Caddy or SSH listeners are never replaced automatically.
