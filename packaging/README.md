# Linux package build and release

Work in progress. Build recipes exist; package compatibility is claimed only after installed-artifact checks pass on the declared release/desktop/architecture. Current production onboarding/default-port/Wayland work remains on the roadmap.

`build-runtime.sh` runs inside Ubuntu22.04, building pinned GStreamer1.26.11 and patched libnice0.1.24. It creates a private runtime closure under `/opt/traverse`; it does not replace system media libraries. The payload includes the external xmessage executable used by the local Stop sharing dialog, required shared libraries and plugin scanner. An existing X11 display/core fonts and the host CA trust store remain prerequisites. The software-only baseline targets glibc2.35 or later; GPU/Wayland support requires its separate backend/hardware evidence.

CI builds native x86_64 and arm64 artifacts on their respective runners. It records the resolved baseline image identity, source commit, dependency versions and payload hashes. Pinning source archives is not a claim of bit-identical output across changing distribution repositories; independent rebuild/provenance comparisons are still required.

Artifacts: `.deb`, `.rpm`, portable `.tar.gz`, SHA256SUMS and corresponding third-party source archives/patch/build recipe/notices. No build toolchain is needed on the installation host. The installed launcher runs as `traverse --config FILE` (default `$XDG_CONFIG_HOME/traverse/config.json`). It supervises its adapter/service children and stops them on exit or crash. Copy the packaged `config.example.json` and supply the origin/certificate/key; integrated first-run host controls and default443 are a later phase. `traverse --check-runtime`, `traverse adapter ...` and `traverse service ...` remain available for diagnostics. Package installation does not activate capture or a listener.

Stable publication requires `vX.Y.Z` matching the CMake version, with the exact tag commit reachable from fully fetched `origin/main`. A dev-only descendant fails even if main is its ancestor. The release rebuild uses the validated commit SHA, runs package installation/relocation/dialog checks and publishes only its own artifacts after checks. Branch/PR workflows have read-only tokens and do not release or receive publishing credentials. Daily builds remain workflow artifacts.

The runtime check encrypts and decodes synthetic VP8 frames without opening a display or network listener. Bundled NSS providers include their matching integrity files; relocation tests also remove a provider to verify that an incomplete payload fails. Plugin discovery alone does not prove encrypted media works.

Native build checks also exercise an experimental shared TLS front end with real socket witnesses. The product launcher does not select or install that front end yet. The explicit `--internal-http` service mode accepts only numeric loopback bindings behind a TLS terminator; ordinary service launches still require HTTPS certificates. Service listeners use address reuse for restart and reject a second live listener on the same address/port.

No project license has been selected. Bundled third-party components retain their licenses and accompanying source/notice obligations; packaging does not relicense them.
