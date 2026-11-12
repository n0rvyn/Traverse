# libnice fixed-port reconnect compatibility

Target: Gentoo libnice 0.1.24, `socket/tcp-passive.c`, passive listener bind.

The installed source calls `g_socket_bind(..., FALSE, ...)`. A locally revoked session left TCP50000 in kernel TIME_WAIT. The next ICE agent successfully created its UDP candidate but failed its passive TCP bind with `G_IO_ERROR_ADDRESS_IN_USE`. libnice then discarded all candidates. The GStreamer gathering state remained incomplete and the service returned an ICE gathering timeout.

Evidence before the patch: `docs/evidence/failures/libnice-bind-results.txt` and the `tcpAfterRevoke` section of the revoke/reconnect probe. The controlled experiment changes only the passive listener's address-reuse flag, rebuilds the same package version and restarts the task-owned service. The authorization boundary, candidate protocols, fixed port and timeout remain unchanged.

The patch enables SO_REUSEADDR through GLib, preserving reuse after teardown. It does not enable SO_REUSEPORT. Verification must include both reconnect and bind-plus-listen exclusion while the real listener remains active.

Install on the authorized Gentoo test host:

```sh
mkdir -p /etc/portage/patches/net-libs/libnice-0.1.24
cp patches/libnice-0.1.24-passive-tcp-reuse.patch /etc/portage/patches/net-libs/libnice-0.1.24/
emerge --oneshot --usepkg=n =net-libs/libnice-0.1.24
```

Review this patch when changing libnice versions. The current build does not send an upstream issue or publish a patch automatically.

## Private capture runtime repairs

The private-runtime build applies five narrow patches to its pinned sources. The host compositor and PipeWire daemon are unchanged. Review every patch when advancing the pinned versions.

| Source | Patch | Reproduced defect and check |
|---|---|---|
| GStreamer 1.26.11 | `gstreamer-1.26.11-unixfd-socket-identity.patch` | Stop unconditionally unlinked a replacement file at the old socket path. Actual replacement-file/listener and adapter pair/revoke tests cover ownership-preserving cleanup. |
| GStreamer 1.26.11 | `gstreamer-1.26.11-unixfd-clock-offset.patch` | A sender clock 30s ahead became receiver timestamps 60s ahead. The same actual Unix-FD sender/receiver test checks both positive and negative offsets. |
| PipeWire 1.6.0 | `pipewire-1.6.0-unset-cycle-timestamp.patch` | With an older server and no timestamp header, unset cycle time 0 made successive changing frames present at time 0. Preserve an unknown timestamp so explicitly enabled GStreamer timestamping supplies running time. Supplied valid timestamps remain intact. |
| PipeWire 1.6.0 | `pipewire-1.6.0-pretransport-mix-cleanup.patch` | Default port mixes were allocated before transport arrived but skipped during cancellation cleanup. The real nonresponsive-protocol fixture covers Stop/restart, revocation and destruction under ASan/UBSan with leak checking enabled. |

| PipeWire 1.6.0 | `pipewire-1.6.0-cancel-on-core-disconnect.patch` | Negotiation waited after the protocol peer disconnected, and an error return could retain the thread-loop lock. Check actual core failure in each wait and release the loop lock on state-transition failure. The optimized real-peer EOF/Stop fixtures and sanitizers retain their original assertions. |

The capture library directly links its libdbus dependency and records the loaded version. PipeWire RT contexts otherwise unload libdbus between captures and lose its process-global cache allocations. No capture Stop calls global `dbus_shutdown`: the [official API contract](https://dbus.freedesktop.org/doc/api/html/group__DBusMemory.html) requires all other libdbus users to have stopped, and warns against calling it from a shared library.

Every patch is copied into the payload and exact third-party source archive by `packaging/package.py`. None is an upstream submission or a stable release claim.

`libnice-0.1.24-dns-gathering-completion.patch` repairs the native ICE completion path after failed STUN/TURN DNS resolution. The original error callbacks removed/marked the failed work but skipped normal gathering finalization. Completion also waits for remaining STUN resolvers, and a late successful lookup checks that its stream still exists. Controlled native tests cover multiple pending lookups, TURN failure, removed streams and close cancellation. An actual installed offline negotiation test returned HTTP400 with host candidates already present; changing only the private libnice library made the same controlled-NXDOMAIN offer/answer and installed lifecycle checks pass. The STUN URI, ICE completion requirement and existing service wait remain unchanged. Detailed experiment evidence is under `docs/evidence/wayland-controller/native/`.

## Private EIS provider ownership repair

`libei-1.5.0-setup-fd-ownership.patch` closes an owned descriptor when event-source registration fails before the source becomes active. The original library returned `-ENOSPC` from a probe-controlled socket registration failure, then left the consumed socket open after context teardown. Changing only this cleanup condition makes the identical probe pass. Normal removal already invalidates the stored descriptor; borrowed descriptors remain excluded from cleanup.

The native `eis-provider-wire` test checks that failure contract plus a real libei/libeis sender handshake, resumed pointer device, absolute motion, frame and disconnect. Its epoll fault shim is linked only into the test executable; the runtime uses no preload or altered host limits. The build applies the repair to the pinned private source and includes it in both package patch notices and the corresponding source archive. This provider test does not establish installed Wayland control.

`libei-1.5.0-pause-emulating-device.patch` repairs the private libeis test server's pause method, which accepted only a resumed device and ignored a device once a sender started emulating. The real sender pause/resume test failed with the original state check and passed after changing only that condition to accept active emulation too. The same wire test verifies deferred release of owned keys/buttons on resume. This server-library repair does not change the distribution's compositor or establish its pause behavior. Both repairs accompany the pinned source archive and payload notices.
