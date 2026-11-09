# Verified compatibility

Package CI run: https://github.com/n0rvyn/Traverse/actions/runs/42565801939
Source commit: `a5a221cc4b85f96f58c247840b7d7de35a77c84c`.

An earlier plugin-only check missed dynamically loaded NSS crypto providers. This run includes the matching providers and integrity files, tests an encrypted VP8 round trip, and rejects a deliberately incomplete portable payload. The repaired Ubuntu-built payload also passed real Chrome video, typing/modifiers, scrolling, pointer mapping, reconnect and disconnect on the Gentoo X11 test host.

| Environment | Architecture | Actual evidence |
|---|---|---|
| Ubuntu22.04 | x86_64, arm64 | Native DEB installation, private GStreamer runtime, portable relocation, real X11 Stop sharing dialog, supervised HTTPS startup, duplicate-instance rejection, orderly/crash cleanup and uninstall |
| Fedora44 container | x86_64, arm64 | RPM installation, private runtime encrypted-video check, RPM file verification and uninstall; no GNOME/KDE desktop claim |
| Gentoo test host | x86_64 | Exact CI portable artifact: archive/payload hashes, encrypted-video check and real Chrome pairing/video/typing/modifiers/scroll/pointer/reconnect/disconnect passed on an existing X11 session; earlier native safety evidence remains separate |

The tested runtime uses GStreamer1.26.11, patched libnice0.1.24 and an Ubuntu22.04 glibc2.35 build baseline. Package metadata records the resolved base-image digest, exact source commit and build dependency versions. Corresponding third-party sources are a separate, larger archive.

Do not infer support for every Debian/RPM release from package format. RHEL-compatible desktop versions, native Wayland, GNOME/KDE sessions, physical keyboard/IME combinations and GPU encoding need their own evidence. Current software-only packages attach to an existing X11 session; they do not create a desktop/login or a browser terminal.

CI artifacts are development builds. No stable release tag has been published. Stable publication requires the reviewed main milestone/version-tag gate described in CONTRIBUTING.md.
