# Verified compatibility

Native host package acceptance passed in [CI run 43248280700](https://github.com/n0rvyn/Traverse/actions/runs/43248280700).
Source commit: `5b5000fa7bbb66acff5a2dd5a5d96db5b17f9525`.

Both architectures passed native host builds and actual installed DEB/RPM/portable X11 lifecycle checks. A separate ordinary Chrome client passed first-run setup, native public-CA export, initial distrust followed by deliberate trust, real 1280×1024 video and keyboard control, Settings continuity, held-input release on Stop, and next-launch port change with the same CA. That browser journey runs on x86_64, with a separate client UID/home/trust database and no certificate or sandbox bypass. It is not a physical desktop or ARM-to-Chrome acceptance claim.

Qt Wayland rendering and packaged guardian tests do not establish integrated Wayland capture/control. GNOME/KDE normal host launch remains separate work.

This run also verifies byte-identical conversion across thread counts and one-CPU affinity selection. It verifies private crypto providers/integrity files, encrypted VP8, incomplete-payload rejection, actual coturn authentication/ACL/datagrams and isolated unprivileged TLS443 permissions. It includes the standalone supervisor and video retransmission/source-identity regression checks, validated certificate rotation/rejection/expiry, supervisor status recovery and selected trust paths after helper environment clearing. Plugin presence alone is insufficient evidence of encrypted media or packet recovery.

| Environment | Architecture | Actual evidence |
|---|---|---|
| Ubuntu22.04 package containers; Ubuntu24.04 ordinary-Chrome runner (x86_64 only) | x86_64, arm64 | Native setup/sharing/Settings/public-export host entry, separate system Qt dependencies, DEB installation, private GStreamer runtime, portable relocation, real X11 Stop sharing, nonroot default443/custom standalone launch, repeated primary/RTX negotiation, certificate renewal/expiry and status-fault recovery with retained TURN/input, orderly/crash/child-failure cleanup, held-key release, port/certificate conflict rejection and uninstall |
| Fedora44 container | x86_64, arm64 | Native host setup/Settings/Stop/relaunch and owner-data preservation, RPM installation, private runtime encrypted video, actual TURN auth/ACL/datagrams, nonroot TLS443 helper, every-thread capability/environment checks before and after certificate refresh, explicit trust-path transport, reinstall, RPM metadata verification and uninstall; no GNOME/KDE desktop claim |
| Gentoo test host, earlier runtime-only proof at a99cec1b | x86_64 | Earlier CI portable artifact: archive and all174 payload hashes, encrypted-video check, ordinary Chrome direct UDP and forced TURN/TLS under a URL prefix, typing/modifiers/scroll/pointer/reconnect/disconnect, actual local Stop while Chrome held Shift, full owned cleanup and stable-service restoration |

The Gentoo row predates the packaged Qt host window and does not verify that window on Gentoo. Current Gentoo system-Qt installation and native host/Chrome acceptance remain open.

The tested runtime uses GStreamer1.26.11, patched libnice0.1.24, coturn4.18.0 and an Ubuntu22.04 glibc2.35 build baseline. Package metadata records the resolved base-image digest, exact source commit and build dependency versions. Corresponding third-party sources are a separate, larger archive. Default443 was tested in isolated package containers; the public Gentoo proof used the already-open custom port and preserved the existing443 website. See [performance evidence](performance.md) for measurement definitions and remaining relay variation.

Do not infer support for every Debian/RPM release from package format. RHEL-compatible desktop versions, native Wayland, GNOME/KDE sessions, physical keyboard/IME combinations and GPU encoding need their own evidence. Current software-only packages attach to an existing X11 session; they do not create a desktop/login or a browser terminal.

CI artifacts are development builds. No stable release tag has been published. Stable publication requires the reviewed main milestone/version-tag gate described in CONTRIBUTING.md.
