# Roadmap

The current native C++/GStreamer slice shares one existing X11 desktop with ordinary Chrome: encrypted video/input, local pairing/Stop sharing, reconnect and an independent input guardian. It has been exercised on Gentoo and real Chrome, including crash/revoke tests. This is not remote login or headless session provisioning.

The automatic certificate backend now has a separate native validation role, a cold issuer process and persistent renewal scheduling. Its private-CA checks cover bootstrap, cached restart, renewal, cancellation and interrupted-order uncertainty. Development packages include first-run local certificate controls; public-provider selection/consent and the remaining desktop/physical acceptance matrix are still active work.

Active delivery work:

1. Native DEB/RPM/portable packages with private, reproducible media dependencies and safe lifecycle.
2. Self-hosted HTTPS URL setup; approved default443 plus configurable port, locally generated certificates selected by default, an existing-certificate option, protocol-aware conflict detection and certificate lifecycle.
3. Native host controls with status first, URL/code Copy buttons, connection checks, Settings and continuously visible Stop sharing. Closing the window stops sharing; New code is available only before pairing and never silently revokes an existing controller. Automatic URL/media checks use an independent, self-hostable observer with truthful failure notifications.
4. GNOME/KDE compatibility on X11 and Wayland through supported desktop consent, PipeWire capture and input APIs.
5. Per-stage performance measurements and equal-quality software/GPU capture/encode/decode comparisons on actual hardware.
6. Verified release/architecture/desktop matrix, package signatures, upgrades, rollback and uninstall.

Repository policy: daily development commits push directly to `dev` without a PR; reviewed milestones merge into `main`. Package CI runs for development; version tags from `main` automatically release packages only after checks pass. A managed connection service/account product is outside the selected self-hosted model.

Native host package builds and installed X11 lifecycle checks passed on both architectures in [CI run 43248280700](https://github.com/n0rvyn/Traverse/actions/runs/43248280700), including the x86_64 ordinary Chrome first-run journey. This does not establish complete distribution/desktop coverage, external reachability notifications, Wayland integration or GPU/physical-performance acceptance. Terminal-only/physical-TTY access remains [documentation-only future work](future-terminal-mode.md), deferred until the current goal is reached.
