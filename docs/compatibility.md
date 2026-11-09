# Verified compatibility

Package foundation CI run: https://github.com/n0rvyn/Traverse/actions/runs/42587764584
Source commit: `a032d0938d78edb7528c1f8b843caf28277ac274`.

An earlier plugin-only check missed dynamically loaded NSS crypto providers. This run includes matching providers/integrity files, an encrypted VP8 round trip and rejection of incomplete portable payloads. It also adds actual coturn4.18.0 authentication/ACL/datagram tests and isolated unprivileged TLS443 helper checks, including every thread, hostile environment, writable files and install/reinstall permissions. An earlier repaired Ubuntu-built payload separately passed real Chrome video, typing/modifiers, scrolling, pointer mapping, reconnect and disconnect on the Gentoo X11 test host.

| Environment | Architecture | Actual evidence |
|---|---|---|
| Ubuntu22.04 | x86_64, arm64 | Native DEB installation, private GStreamer runtime, portable relocation, real X11 Stop sharing dialog, supervised HTTPS startup, duplicate-instance rejection, orderly/crash cleanup and uninstall |
| Fedora44 container | x86_64, arm64 | RPM installation, private runtime encrypted video, actual TURN auth/ACL/datagrams, nonroot TLS443 helper, every-thread capability/environment checks, reinstall, RPM metadata verification and uninstall; no GNOME/KDE desktop claim |
| Gentoo test host | x86_64 | Exact CI portable artifact: archive/payload hashes, encrypted-video check and real Chrome pairing/video/typing/modifiers/scroll/pointer/reconnect/disconnect passed on an existing X11 session; earlier native safety evidence remains separate |

The tested runtime uses GStreamer1.26.11, patched libnice0.1.24, coturn4.18.0 and an Ubuntu22.04 glibc2.35 build baseline. Package metadata records the resolved base-image digest, exact source commit and build dependency versions. Corresponding third-party sources are a separate, larger archive. These foundation checks are distinct from the versioned standalone launcher/default443 integration and its exact-artifact Chrome acceptance.

Do not infer support for every Debian/RPM release from package format. RHEL-compatible desktop versions, native Wayland, GNOME/KDE sessions, physical keyboard/IME combinations and GPU encoding need their own evidence. Current software-only packages attach to an existing X11 session; they do not create a desktop/login or a browser terminal.

CI artifacts are development builds. No stable release tag has been published. Stable publication requires the reviewed main milestone/version-tag gate described in CONTRIBUTING.md.
