#!/bin/bash
# Exact retained artifact; no runtime compilation, owner logs or host changes.
set -euo pipefail
dnf --setopt=keepcache=True install -y /src/dist/*.rpm
traverse --check-runtime
dnf --setopt=keepcache=True install -y python3 python3-gobject dbus-daemon openssl util-linux xorg-x11-server-Xvfb xorg-x11-fonts-misc gcc libX11-devel libXtst-devel
mkdir -p /src/.work/renewal-diagnostics
python3 - <<'PY'
from pathlib import Path
import hashlib,json,os,subprocess
prefix=Path('/opt/traverse');manifest=json.loads((prefix/'share/traverse/runtime-manifest.json').read_text())
assert manifest['sourceCommit']=='76b06afe55c5caa595d74b8a92450d7d33937899'
assert manifest['architecture']=='aarch64' and os.uname().machine=='aarch64'
versions=subprocess.check_output(['rpm','-q','glibc','openssl-libs','qt6-qtbase','qt6-qtbase-gui','qt6-qtwayland','python3'],text=True).splitlines()
Path('/src/.work/renewal-diagnostics/inputs.json').write_text(json.dumps({'sourceCommit':manifest['sourceCommit'],'architecture':manifest['architecture'],'userland':Path('/etc/os-release').read_text(),'packages':versions,'launcherSha256':hashlib.sha256((prefix/'libexec/traverse/traverse-launcher').read_bytes()).hexdigest(),'fixtureOnlyChanges':True},indent=2)+'\n')
PY
gcc /src/tests/x11_input_probe.c -o /tmp/x11-probe -lX11 -lXtst
gcc /src/tests/x11_capture.c -o /tmp/x11-capture -lX11
export TRAVERSE_TEST_FAILURE_ARTIFACTS=/src/.work/renewal-diagnostics
export TRAVERSE_TEST_RENEWAL_DIAGNOSTICS=1
xvfb-run -a python3 /src/tests/installed_managed_certificates.py
