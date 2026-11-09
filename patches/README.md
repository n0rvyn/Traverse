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
