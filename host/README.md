# Native host window

This is the native host development target for the approved setup, sharing,
Settings and public CA export windows. Private x86_64 package candidates now
include the explicit `traverse-host` entry; published CI artifacts have not yet
been updated. Actual installed DEB/RPM and relocated portable setup, native input cleanup,
Stop/relaunch and owner-data preservation checks passed in isolated X11 tests.
The exact-package Chrome journey currently fails when the supervisor loses
desktop-adapter IPC. Desktop and remaining package acceptance stay open; see
local verification records, which stay outside public history.

The UI links system Qt6 and runs separately from the private media runtime. It
obtains the native runtime environment before creating its private owner socket,
then directly starts the owned supervisor. It does not parse owner logs.

Build on Linux with Qt6.2 or newer development libraries (including the OpenGL
headers required by QtGui), CMake, a C++17 compiler, OpenSSL development libraries
and nlohmann-json headers. Tests also use Python3
and the OpenSSL executable:

```sh
cmake -S host -B .work/build-host
cmake --build .work/build-host
ctest --test-dir .work/build-host --output-on-failure
```

The CTest target uses independent synthetic producers to check framing, live
status, identity, correlation and stale-state behavior. Settings storage tests
use real files and explicit I/O faults: a successful save requires durable
replacement and matching readback. An uncertain replacement requires rereading
the actual file before another save. Storage does not restart sharing or enroll
certificates. The separate
`tests/host_window_lifecycle.py` fixture exercises actual controls, cross-process
clipboard, the native runtime and a private CA under UID65534 in a disposable
Linux container/namespace. It must not run against an operator's existing host.

The internal entry requires a private runtime prefix (`--prefix`). An absent
configuration opens setup; `--config` selects an explicit path, otherwise the
path is `$XDG_CONFIG_HOME/traverse/config.json` or
`$HOME/.config/traverse/config.json`. Setup creates the file only after Start
sharing and refuses to overwrite any existing entry. It keeps the legacy local safety dialog until replacement
acceptance. Settings uses the shared native endpoint form and existing atomic
configuration store. Successful Save says “Saved. Changes take effect the next
time you launch Traverse.” It does not restart the current endpoint or revoke
the controller; closing Settings leaves sharing running.

Actual Qt and isolated X11 checks cover Save/readback/reopen, invalid fields,
pre-commit failure, uncertain replacement, preserving configured automatic
certificate fields, and closing during pending reads. A separate real window
journey over the exact portable runtime checks pairing and held input through
Save, unchanged active URL/clipboard/token, next-launch port/root persistence,
and Stop/close/GUI death while Settings is open. This is development-target
verification, not installed first-run, GNOME/KDE or physical-latency acceptance.

Local HTTPS readiness enables Export CA certificate. The standard save dialog
exports only the active checked public root; it never installs client trust.
The native producer and Qt consumer share hostname-restricted certificate
validation. The output uses atomic replacement without direct-write fallback;
cancel/failure preserves the controller, and Stop cancels pending work without
waiting for disk I/O. Supplied-certificate mode has no local CA export.

Current evidence in `docs/evidence/first-run-local-trust/` covers actual setup
without handwritten JSON, native export, deliberate trust of that exported file
in a separate ordinary Chrome UID/home/NSS database, real video/key input,
Settings continuity, Stop release/cleanup, and next-launch new-port/same-CA trust.
Light/dark and 640×480 at 200% checks include visible actions, scrollable fields,
save/cancel/overwrite, actual disk errors and pending-write cleanup. These runs
use the current native app/launcher over a byte-verified portable runtime basis,
not a newly assembled UI package. No real Mac/system trust was changed.
