# Reachability verifier

The private native `traverse-readiness-verifier` worker performs one HTTPS challenge against one explicitly configured numeric address. It is the transport component for the self-hosted observer. The server below provides authenticated operator registrations and DNS/address admission. Configured native host orchestration is undergoing installed-package acceptance; media checks and observer deployment remain product work.

The trusted caller writes one JSON request to stdin and closes the pipe. Do not put credentials in arguments, environment variables or logs. Only the internal `--supervisor-pid` option is accepted alongside direct stdin-only mode. The worker creates no listener, desktop session, controller or child process.

Request fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Integer `1` |
| `target.host` | TLS certificate identity, SNI, Host and Origin hostname |
| `target.port` | Explicit HTTPS port, integer 1–65535 |
| `target.basePath` | Canonical Traverse base path |
| `target.address` | Explicit numeric IPv4/IPv6 connection pin |
| `target.caFile` | Operator-selected existing CA bundle; empty uses system trust |
| `lease` | Exact fresh private-owner `instance`, `id`, `token`, `nonce` |

Only trusted operator configuration can supply the target, pin or CA file. Private/LAN addresses work when explicitly supplied. This worker does not authorize arbitrary addresses from a public registration request. Any public caller must enforce an operator-owned target policy before spawning a worker and validate each resolved address; the server below provides that boundary. There is no hostname-resolution fallback or redirect following. Certificate and hostname verification stay enabled. Port success is transport evidence; it does not prove Chrome permits that port.

Private stdout contains schema version and `status`. Success is `received` with a receipt containing the matching instance, job ID, nonce and remote observation timestamp. The caller must compare this receipt with the same live service's native-owner inspection, end the lease, and attach independently established observer-vantage metadata. Remote monotonic time is not comparable with the caller's clock. Never infer external or media readiness from the owner's arrival state alone.

Failures contain only one stable status: `invalidRequest`, `connectionFailed`, `tlsFailed`, `httpRejected`, `invalidReceipt` or `internalFailure`. No failure contains the remote body or credentials. HTTP errors and redirects both use `httpRejected`; the worker does not claim a more specific network diagnosis than its evidence supports.

The supervisor owns cancellation and exact reaping. Terminating the worker closes its sockets even during connect/TLS/response waits. The supervisor must also end its service-side lease on success, failure and cancellation. Existing HTTP-library timeouts remain; this component introduces no new app deadlines or quotas. Tests use explicit watchdogs.

No worker result currently changes host UI readiness. The host continues to report external reachability as unknown until the complete observer flow is connected and independently verified.

## Configured native host checks under acceptance

A schema-version 1 host configuration can include explicit observer metadata:

```json
"observerSettings": {
  "host": "observer.example.test",
  "port": 443,
  "caFile": "observer-root.pem",
  "registrationId": "11111111111111111111111111111111",
  "tokenFile": "registration.key",
  "timeoutMs": null
}
```

This is an operator example, not a deployed observer or a selected setup default. Relative file paths use the host configuration directory. `caFile` can be empty to use the existing system roots. A supplied CA is read through a trusted regular-file descriptor and loaded into the HTTPS client from memory. The registration file contains the observer's 64 lowercase hexadecimal credential, optionally followed by one newline or CRLF; it must belong to the host process user, be owner-only, and cannot be a final symlink. The configuration and custom CA must belong to that user or root, have no group/other write permission, and cannot be final symlinks. Inline credentials are rejected.

`timeoutMs` is required in this metadata while the product deadline default remains unchosen. A positive integer bounds the URL check; `null` adds no overall deadline beyond the existing transport deadlines. It never ends control or changes pairing authority.

After local HTTPS startup, the native manager resolves through the authenticated observer, creates a parent-known reservation per admitted address, and streams results from a guarded helper. A separate operation compares receipts with the live native owner and cancels every reservation. Full verification requires all receipts and all cleanup acknowledgements. Partial address results remain separate. Missing cleanup acknowledgement retains the known IDs and prevents a new batch until explicit retry confirms revocation. Cancelled IDs cannot be reserved later in the same service lifetime.

The private owner snapshot exposes `urlCheck` without bearer credentials, pairing codes or credential paths. The private `check-connection` action requests a retry and rejects overlap. Kernel route/address/link events, resolver/hosts/NSS changes, and certificate revision/availability changes invalidate earlier results. Watcher failure is explicit through `networkObservation`; it does not stop control. UI status, Retry placement, notifications and first-run configuration remain separately gated design work.

A matched receipt proves this observer reached the configured HTTPS endpoint at check time. `externalReachability` and media status remain `unknown`: neither a same-host observer nor its random instance ID proves Internet reachability, WebRTC transport, or rendered frames.

## Authenticated observer server

The private argument contract is `libexec/traverse/traverse-readiness-observer --config /absolute/private/observer.json`. Its native caller must apply the installed prefix environment returned by `traverse --runtime-environment` before executing it, as with the existing private helpers. The private ELF does not locate bundled libraries by itself. This starts an explicitly configured TLS listener; completed operator setup remains product work. Nothing enables or deploys this service automatically. The config must be an owner-only regular file; final symlinks and public permissions are rejected. It requires explicit `schemaVersion:1`, numeric `listenAddress`, `port`, existing `certificate` and `privateKey` absolute paths, and `registrations`. There is no implicit observer port or CA enrollment.

Each registration has a distinct 32-character lowercase hex `id`, a distinct 64-character lowercase hex `token`, and `target` with `host`, `port`, `basePath`, `caFile`, and nonempty `allowedAddresses`. Addresses are explicit numeric unicast grants. Duplicate IDs, credentials and canonical address entries fail startup. These grants belong to the operator; an HTTP caller cannot change them. Do not reuse a Traverse controller credential as an observer registration token.

Both routes require exactly one `X-Traverse-Registration` header and one `Authorization: Bearer …` header. Credentials are checked before JSON decoding or DNS/target work. Browser `Origin` requests are rejected; this is an authenticated host-to-observer protocol.

| Route | Body | Successful evidence |
| --- | --- | --- |
| `POST /v1/resolve` | `schemaVersion:1` | `status:resolved`, approved current addresses |
| `POST /v1/check` | `schemaVersion:1`, `address`, fresh `lease` | `status:received`, actual target receipt and checked address set |

Address selection uses the observer's OS resolver with AF_UNSPEC/SOCK_STREAM and preserves its NSS order, hosts files and other providers. A literal IP or a complete, current hosts-file corroboration needs no DNS lookup. Hosts corroboration means the selected addresses also appear in exact canonical-name/alias entries; it does not assert which NSS provider produced them. Every matching hosts entry, selected OS address and usable DNS answer must satisfy the immutable registration grant; an extra unapproved address rejects the result rather than being discarded.

Successful resolve/check responses require a `resolution` object: `schemaVersion:1`, `basis` (`literal`, `hosts` or `system`) and `dns` with `a`/`aaaa` family objects. Each family has `status` (`notChecked`, `answered`, `absent` or `failed`) and canonical `addresses`. Literal/hosts results use `notChecked` with empty arrays. For other system names, supported per-instance resolver queries check the configured name's exact A/AAAA records independently. OS search-suffix and other NSS resolution remain available for address selection; the DNS evidence does not claim those were exact-name DNS answers. Empty/NXDOMAIN differs from SERVFAIL, timeout or malformed response. Resolver settings that suppress a family cannot fabricate a successful family check.

A positive pinned HTTPS receipt remains useful when OS-name resolution works and DNS has a failed family; the manager retains that receipt but reports the combined check as `partial`, with `dnsFailed` and explicit family evidence. Hosts-backed LAN and literal-IP HTTPS can verify with DNS `notChecked`. OS-only names with absent DNS retain URL reachability without a DNS-ready claim. Evidence is compared again on every check, including its basis and both family results. Missing, contradictory or changed evidence fails closed; use matching-build observer and host components.

These are the checking machine's resolver and hosts files. A Chrome client needs its own working mapping for the same URL name. A LAN observer's receipt proves that LAN vantage, not Internet reachability. Neither local hosts success nor absent/unchecked DNS establishes a public DNS view, media readiness or future answers.

The caller creates a separate service lease per resolved address. It authenticates the observer's TLS identity, verifies the returned receipt against its live native owner, ends each lease, and records the operator-established vantage. All results include a random `observerInstance` for that server lifetime. That value alone does not prove outside-network placement. No callback is trusted and no result currently changes the host's external-readiness UI.

Checks own their DNS/HTTPS child until exact reap. Closing the requesting connection or stopping the observer terminates that child; observer death also triggers the worker's Linux parent-death guard. Existing `OwnedOperation` handles the private pipe, cancellation and reaping. The verifier now accepts its internal `--supervisor-pid` argument as well as direct stdin-only mode. The private DNS worker protocol uses schema version 2; the existing HTTPS worker JSON remains version 1.

Auth failure returns HTTP 403, malformed/forbidden request shape returns 400, and internal protocol failure returns 503. Completed check failures use HTTP 200 with `dnsFailed`, `dnsMismatch`, `connectionFailed`, `tlsFailed`, `httpRejected` or `invalidReceipt`; they are never success evidence. Responses are `no-store` and contain no registration/probe bearer or remote error body. This server performs no desktop capture/input and does not consume the real controller slot.

Process ownership follows the Linux creator-thread rule documented in [PR_SET_PDEATHSIG](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html); resolver hints/error handling follow [getaddrinfo](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html). Synchronous handlers remain alive through child reap. Native host scheduling/lease cleanup, authenticated observer setup/deployment, synthetic WebRTC, outside-vantage acceptance and host notifications remain required product work.
