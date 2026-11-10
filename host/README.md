# Native host window

This is the configured-host development target for the approved sharing window.
It is not installed by the current packages. Settings, first-run onboarding and
complete desktop/package acceptance remain in the productization plan.

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

The internal entry requires an existing versioned configuration and private
runtime prefix. It keeps the legacy local safety dialog until replacement
acceptance; the incomplete Settings button is not a released product behavior.
No first-run trust choice or public certificate provider is selected here.
