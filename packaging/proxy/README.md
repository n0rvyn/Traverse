# Optional shared-port gateway

This module only recognizes the reserved native probe ALPN namespace. It does
not validate a lease, choose an upstream from a request, or grant remote control.
Unknown, malformed, mixed and revoked probe offers still reach native admission.
No-ALPN traffic remains available to the gateway's HTTPS/TURN classifier.
`acme-tls/1` remains with the public gateway certificate provider.

The ordinary Linux packages do not require Go or Caddy. Shared-gateway integration
is tested separately from direct-host startup. These sources do not install a
gateway, change a running service, issue a public certificate or open a port.

For the current Caddy2.10.2/Go1.27 family, build from the operator's retained
prepared source so its existing source corrections and module imports survive:

```sh
python3 packaging/build-proxy.py \
  --caddy-source /path/to/prepared-caddy-source \
  --work /path/to/new-owned-build \
  --version-label traverse-proxy-candidate
```

The input source remains unchanged. The builder excludes its vendor cache,
preserves its module imports, adds the pinned Caddy-L4 module and maintained
HTTP2 bridge, and retains the Go1.25 compatibility defaults. It uses Go1.27 and
authenticated module sums. `GOMODCACHE` can point at an existing authenticated
build cache. All new objects stay under `--work`.

Before using the candidate, run both generated Linux test binaries on the target:

```sh
./caddy-identity-test -test.run '^TestTraverseJSONTypeIdentity$'
./probe-matcher-test
```

The identity test checks the existing Caddy RawMessage correction, including
rejection of ordinary byte maps. The build receipt means “built”, not “accepted”.
The final candidate also needs the strict TLS/HTTP2/path/TURN/native authority
and certificate-provider tests. Live proxy changes require separate approval.

The handshake matcher has no arguments:

```caddyfile
tls {
    traverse_probe
}
```

Its JSON form is `{"tls":{"traverse_probe":{}}}` inside a layer4 route matcher.
This fragment alone is not a complete shared HTTPS configuration.

For a native test build, `-DTRAVERSE_TEST_PROXY_BINARY=/path/to/caddy` adds
`readiness-shared-proxy`. It uses the real observer, source, adapter and strictly
verified gateway with separate public/probe roots, real pairing priority and
crossed-root negatives. The gateway is optional and is never a package runtime
dependency. Run this fixture in the same isolated offline environment as the
other native network/desktop tests.

Keep certificate management explicit when the Layer4 handler terminates TLS:
turn off the HTTP app's automatic TLS wrapping and list managed names under the
TLS app's `certificates.automate`, retaining its ACME issuer policy. Disabling the
HTTP wrapper does not disable that explicit certificate management. The actual
synthetic-CA test covers this ownership on443. Avoid adding another TLS wrapper
around the already decrypted HTTP stream.
