# Roadmap

The current native C++/GStreamer slice shares one existing X11 desktop with ordinary Chrome: encrypted video/input, local pairing/Stop sharing, reconnect and an independent input guardian. It has been exercised on Gentoo and real Chrome, including crash/revoke tests. This is not remote login or headless session provisioning.

Active delivery work:

1. Native DEB/RPM/portable packages with private, reproducible media dependencies and safe lifecycle.
2. Self-hosted HTTPS URL setup; default443 proposal plus configurable port, protocol-aware conflict detection and certificate lifecycle.
3. Native host controls and automatic URL/media checks through an independent, self-hostable observer; truthful failure notifications.
4. GNOME/KDE compatibility on X11 and Wayland through supported desktop consent, PipeWire capture and input APIs.
5. Per-stage performance measurements and equal-quality software/GPU capture/encode/decode comparisons on actual hardware.
6. Verified release/architecture/desktop matrix, package signatures, upgrades, rollback and uninstall.

Repository policy: daily development and PRs use `dev`; reviewed milestones merge into `main`. Package CI runs for development; version tags from `main` automatically release packages only after checks pass. A managed connection service/account product is outside the selected self-hosted model.

The package/CI foundation does not imply that later onboarding, default-port, Wayland or GPU work is finished. Terminal-only/physical-TTY access remains [documentation-only future work](future-terminal-mode.md), deferred until the current goal is reached.
