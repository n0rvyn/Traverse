# Contributing

`dev` is the default branch for daily work. Open feature/fix pull requests against `dev`. Merge a reviewed milestone from `dev` into `main`; keep both branches' history and avoid force pushes. Follow-up work returns to `dev`.

CI checks source and builds Linux packages on branch pushes and pull requests. Branch packages are development artifacts, not stable releases. A semantic version tag (`vX.Y.Z`) on `main`, matching the CMake project version, triggers tested package publication. Tags outside `main`, mismatched versions and failed tests cannot publish a stable release. Never reuse or move a published tag.

Normal milestone merges into `main` require up-to-date source tests and package checks for both x86_64 and arm64. Pull requests preserve the milestone review point; force pushes and branch deletion are disabled. The repository owner retains the existing administrator bypass.

Use conventional commit messages. Include the concrete user-visible behavior and actual validation in pull requests. Do not commit credentials, certificates, private deployment settings, raw session traces or pairing-code screenshots. Local operational evidence stays outside public history.

Desktop work must retain local revoke, safe held-input release, encryption, one-controller authorization and the existing desktop. Capture/backend support is established by actual desktop tests, not by a package-install result. Never claim a package supports an untested distribution/session/hardware combination.

Public source availability does not choose a project license. Until an explicit license is selected by the owner, no additional reuse license is granted. Third-party runtime components retain their own licenses and notices.
