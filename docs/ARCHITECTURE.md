# Custode Contained Harness Gateway Architecture Specification

Status of This Memo

This document is an internal project specification written in an RFC-style
Markdown form. The document borrows structure and editorial discipline from
RFC 7322 and uses RFC 2026 as process vocabulary for maturity, review, and
applicability.

This document is the concrete architecture for Custode. It is derived from
[IDEA.md](IDEA.md), which is authoritative for goals, scope, non-goals, and
invariants. When this document conflicts with [IDEA.md](IDEA.md),
[IDEA.md](IDEA.md) takes precedence.

Section 17 is non-normative sequencing guidance. Section 19 is a
non-normative open-issue list. Staged decisions MUST NOT weaken the invariants
in [IDEA.md](IDEA.md).

Abstract

This document specifies the architecture for a Docker Compose project that runs
an untrusted harness container behind a small Rust provider gateway. The
architecture uses one multi-stage Dockerfile with a Debian-based harness target,
a Debian-based Rust builder target, and a `scratch` provider gateway target.
Compose attaches the harness only to an internal network and attaches the
gateway to both the internal network and an egress network. The gateway is an
origin-form HTTP gateway, not an `HTTPS_PROXY` tunnel: it denies `CONNECT`,
allows only configured provider API methods and paths, forwards end-to-end
provider headers without interpreting authentication, forwards to exactly one
configured upstream provider origin, and writes newline-delimited JSON audit
events for every decision.

Table of Contents

- [Section 1: Introduction](#1-introduction)
- [Section 2: Requirements Language](#2-requirements-language)
- [Section 3: Sources](#3-sources)
- [Section 4: Foundations](#4-foundations)
- [Section 5: Toolchain and Gates](#5-toolchain-and-gates)
- [Section 6: Repository Shape](#6-repository-shape)
- [Section 7: Dependency Direction](#7-dependency-direction)
- [Section 8: Gateway Protocol](#8-gateway-protocol)
- [Section 9: Gateway Configuration](#9-gateway-configuration)
- [Section 10: Gateway Runtime Flow](#10-gateway-runtime-flow)
- [Section 11: Audit Log](#11-audit-log)
- [Section 12: Container Images](#12-container-images)
- [Section 13: Compose Topology](#13-compose-topology)
- [Section 14: Runtime Hardening](#14-runtime-hardening)
- [Section 15: Harness Contract](#15-harness-contract)
- [Section 16: Testing Architecture](#16-testing-architecture)
- [Section 17: Initial Build Plan](#17-initial-build-plan)
- [Section 18: Reliability and Security Considerations](#18-reliability-and-security-considerations)
- [Section 19: Open Issues](#19-open-issues)
- [Section 20: References](#20-references)

## 1. Introduction

Custode runs an untrusted agent harness in one container and a provider gateway
in another. The harness can edit only mounted files and can reach only the
internal Compose network. The provider gateway is the only process with
external provider egress.

This document specifies the concrete mechanisms that realize the requirements
in [IDEA.md](IDEA.md). The architecture is a Technical Specification in the
RFC 2026 sense: it describes a concrete service, procedure, convention, and
format for this project.

## 2. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here.

Lowercase uses of these words have their ordinary English meanings.

## 3. Sources

The authoritative source is:

- [IDEA.md](IDEA.md), which is authoritative for goals, scope, non-goals, and
  invariants.

Reference inputs are:

- Docker Compose local development workflows;
- Docker internal networks;
- Rust service binaries built with `cargo`;
- provider SDKs that can be configured with a provider base URL;
- RFC-style sibling project specifications under `../*/docs/`.

## 4. Foundations

The implementation uses these concrete foundations:

- Language: Rust, edition 2024.
- Toolchain: a pinned nightly channel recorded per commit in
  `rust-toolchain.toml`.
- Async runtime: Tokio.
- HTTP server: Hyper through Axum.
- HTTP client: Reqwest with Rustls TLS and no native TLS dependency.
- URL representation: `url::Url`.
- Serialization: Serde and `serde_json`.
- Request digest: BLAKE3.
- CLI parsing: Clap, with environment variable bindings declared on the
  argument types.
- Timestamps: `humantime` RFC 3339 formatting.
- Error modeling: `thiserror` typed errors owned per module.
- Diagnostics: `tracing` with `tracing-subscriber`, enabled by `RUST_LOG`.
- HTTP plumbing: `futures-util`, the `http` crate, `http-body-util`, and
  `tokio-stream`.
- Test tooling: `proptest`, `pretty_assertions`, `tempfile`, and `tower` as
  dev-dependencies, with `cargo-mutants` mutation testing configured by
  `.cargo/mutants.toml`.
- Container composition: Docker Compose.
- Harness Linux distribution: Debian `trixie-slim`, pinned by digest.
- Gateway builder image: official Rust `1-trixie`, pinned by digest.
- Gateway runtime image: `scratch`.
- Static target: native Linux musl for the build platform. The initial
  Dockerfile maps `amd64` to `x86_64-unknown-linux-musl` and `arm64` to
  `aarch64-unknown-linux-musl`.
- Gateway process user: numeric non-root user `65532:65532`.

The selected runtime base is Debian `trixie-slim` because it is a current
stable Debian release, has a conventional security update process, and has a
small official slim image. The gateway builder also uses a Trixie-family image
so the gateway is built on the same Linux distribution family as the harness
runtime.

The currently recorded image index digests are:

- `debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2`
- `rust:1-trixie@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376`

Digest updates are ordinary maintenance work and MUST NOT change the container
trust model.

## 5. Toolchain and Gates

The local gate vocabulary is:

- `just fmt` runs `cargo fmt --all`; `just fmt-check` runs the check form.
- `just lint` runs Clippy for all targets and all features.
- `just test` runs the Rust test suite, including property and integration
  tests.
- `just docs` runs Markdown linting with `mado`.
- `just deny` runs `cargo deny check`.
- `just dockerfile-check` runs the BuildKit Dockerfile check.
- `just docker-build` builds both images; `just docker-test` runs the
  container tests in `scripts/container-test.sh`.
- `just coverage` reports `cargo llvm-cov` coverage.
- `just mutants` runs `cargo-mutants` mutation testing.
- `just check` runs formatting, linting, tests, and the Dockerfile check.
- `just ci` runs `check` plus `deny`.

Gates never skip silently: a recipe fails when its tool is missing rather
than reporting success without running.

The Rust lint posture denies warnings, missing docs, unsafe code, future
incompatibilities, unused dependencies, and broad Clippy lint groups.
Suppressions MUST NOT be used to hide warnings. If a
site-local lint exception is needed, it MUST use
`#[expect(..., reason = "...")]` and the reason MUST explain the invariant.

## 6. Repository Shape

The repository layout is:

```text
custode/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── justfile
├── Dockerfile
├── compose.yaml
├── README.md
├── .cargo/
│   ├── config.toml
│   ├── clippy.toml
│   ├── deny.toml
│   └── mutants.toml
├── docs/
│   ├── IDEA.md
│   └── ARCHITECTURE.md
├── scripts/
│   └── container-test.sh
├── secrets/
│   └── env.example
├── src/
│   ├── adapters.rs
│   ├── allowlist.rs
│   ├── audit.rs
│   ├── body.rs
│   ├── config.rs
│   ├── gateway.rs
│   ├── headers.rs
│   ├── health.rs
│   ├── http.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── ports.rs
│   ├── process.rs
│   └── sim.rs
└── tests/
    └── gateway.rs
```

The root crate produces one binary, `custode-proxy`, and one library crate.
The library owns the gateway state machine, configuration parsing, allowlist
decisions, audit event model, and request forwarding plan. The binary wires the
library to process I/O, signal handling, HTTP sockets, and the container
runtime.

Initial module ownership is fixed as:

```text
src/lib.rs             Library exports
src/main.rs            Binary entry point
src/adapters.rs        Production audit, clock, request-id, and Reqwest adapters
src/config.rs          Gateway configuration and fail-closed parsing
src/allowlist.rs       Target syntax acceptance (AcceptedTarget) and the
                       AllowedTarget allowlist witness
src/audit.rs           Audit event schema and writer
src/gateway.rs         Request handling state machine
src/http.rs            Axum request and response wiring
src/headers.rs         Hop-by-hop and redaction rules producing the
                       ForwardedRequestHeaders witness
src/body.rs            Bounded body accounting and BLAKE3 digests
src/health.rs          Healthcheck subcommand probe
src/ports.rs           Runtime port traits and pure request/response values
src/process.rs         Command-line interface, dispatch, and exit codes
src/sim.rs             Test-only deterministic runtime adapters
```

There is no central error module: each module owns its typed `thiserror`
error, and HTTP status mapping lives in `http` at the runtime edge.

Example-based unit tests live inline in each source file's `tests` module,
and property-based tests live in the same file's `proptests` module.
End-to-end tests that exercise the binary live in `tests/gateway.rs`.

These module names SHOULD remain stable through the initial product. A module
name MAY change only when the old name would become misleading after a
contraction of scope. A rename MUST preserve the ownership boundaries in this
section and the dependency direction in Section 7.

## 7. Dependency Direction

The library dependency direction is:

- `config` depends on primitive parsing, `url::Url`, and typed config errors.
  Environment variable names are declared as clap bindings on the raw
  argument types; the binary edge performs the actual environment read.
- `allowlist` depends on `config` types and owns pure allow/deny decisions.
- `body` owns byte limits and digest accounting. It MAY use Axum body types
  as its byte-stream representation but MUST NOT depend on the server
  runtime.
- `headers` owns header filtering and redaction rules.
- `audit` depends on typed request and response summaries, on `config` for
  audit writer settings, and on accepted targets from `allowlist`, which it
  converts into audit targets. It does not depend on the HTTP server
  runtime. The audit writer owns the log file and performs the only
  filesystem mutation in the library.
- `ports` depends on `audit`, `body`, `config`, allowlist-proven
  `AllowedTarget` values from `allowlist`, and the `ForwardedRequestHeaders`
  witness from `headers`. It owns runtime port traits and pure upstream
  request and response values. `UpstreamRequest::from_target` consumes
  proof-carrying target and header witnesses plus an `UpstreamDeadline`, not
  merely syntax-accepted targets.
- `adapters` depends on `ports`, `audit`, and concrete runtime libraries. It
  owns the production audit sink, clock, request-id source, Reqwest upstream
  client, and reqwest error classification.
- `gateway` depends on `config`, `allowlist`, `body`, `headers`, `audit`,
  and runtime ports. It owns no concrete I/O clients.
- `http` depends on `gateway`, `ports`, `adapters`, and the pure decision
  modules (`allowlist`, `audit`, `body`, `config`, `headers`). It owns Axum
  request and response wiring, builds production adapters at the process
  edge, and calls upstream clients through the `UpstreamClient` port.
- `health` depends on no other library module and owns the healthcheck
  subcommand's TCP probe.
- `process` depends on `config`, `health`, and `http`; it owns the CLI,
  command dispatch, and process exit codes.
- `main` depends on `process` and owns process startup.

Pure decision modules MUST NOT depend on Reqwest, the Axum server runtime,
Tokio sockets, or process environment reads. Runtime modules adapt those pure
decisions to I/O.

## 8. Gateway Protocol

The gateway listens for HTTP requests from the harness on the internal network.

Incoming requests MUST use origin-form request targets. The accepted request
shape is:

```text
METHOD /provider/api/path?query HTTP/1.1
Host: proxy:8080
```

The gateway MUST reject:

- `CONNECT` requests;
- absolute-form and other authority-bearing targets, such as
  `https://api.openai.com/v1/responses` and authority-form request lines
  like `evil.example:443`;
- paths that do not start with `/`;
- paths containing invalid percent-encoding;
- paths containing literal or percent-encoded `.` or `..` segments, so the
  allowlist decision and the upstream URL are computed from the same path;
- method-path pairs absent from the configured operation allowlist, where each
  allowed operation binds exactly one method to exactly one exact path or
  segment-bounded path prefix.

The gateway constructs the upstream URL by joining the configured provider
origin with the accepted path and query. The incoming `Host` header does not
select the upstream host.

The initial protocol surface is HTTP request and response forwarding with
streaming response support. WebSockets, arbitrary TCP, UDP, DNS forwarding, and
HTTP `CONNECT` are not part of the gateway protocol.

## 9. Gateway Configuration

The initial gateway configuration comes from environment variables. Every
variable is also available as a `--flag` on the `serve` subcommand, and flags
override environment values:

```text
CUSTODE_BIND=0.0.0.0:8080
CUSTODE_UPSTREAM_ORIGIN=https://api.openai.com
CUSTODE_ALLOWED_OPERATIONS=GET:exact:/v1/models,POST:prefix:/v1/responses,POST:prefix:/v1/chat/completions
CUSTODE_AUDIT_LOG=/var/log/custode/proxy.ndjson
CUSTODE_REQUEST_TIMEOUT_SECS=120
CUSTODE_MAX_REQUEST_HEADER_BYTES=32768
CUSTODE_MAX_REQUEST_BYTES=10485760
CUSTODE_MAX_RESPONSE_HEADER_BYTES=65536
CUSTODE_MAX_RESPONSE_BYTES=104857600
CUSTODE_MAX_CONCURRENT_REQUESTS=8
CUSTODE_MAX_AUDIT_EVENT_BYTES=16384
```

`CUSTODE_UPSTREAM_ORIGIN` and `CUSTODE_ALLOWED_OPERATIONS` have no defaults:
leaving either unset or empty is a startup configuration error. The
remaining variables default to the values shown above.

Configuration parsing is fail-closed:

- `CUSTODE_BIND` MUST parse as a socket address.
- `CUSTODE_UPSTREAM_ORIGIN` MUST parse as an HTTP or HTTPS URL with scheme,
  host, and optional port, MUST NOT include path, query, fragment, or
  userinfo credentials, and MUST NOT use a wildcard host.
- `CUSTODE_ALLOWED_OPERATIONS` MUST contain at least one operation.
- Each operation MUST have the form `METHOD:exact:/path` or
  `METHOD:prefix:/path`.
- Every configured path or prefix MUST begin with `/`.
- Prefix matching MUST be segment-bounded: `/v1/responses` matches
  `/v1/responses` and `/v1/responses/{id}`, but not `/v1/responses-other`.
- Size, concurrency, and duration bounds MUST be positive.

A later file-based config MAY replace environment parsing, but it MUST keep the
same fail-closed semantics.

## 10. Gateway Runtime Flow

For each request, the gateway performs these steps in order:

1. Acquire a concurrency admission permit before allocating the request
   identity. A refused request is audited as a `denied` decision with error
   class `too_many_requests` and answered with HTTP 429.
1. Allocate a request identity.
1. Parse and validate the method and origin-form target, rejecting literal or
   percent-encoded dot segments.
1. Check the method-path operation allowlist.
1. Copy end-to-end headers, excluding hop-by-hop headers, the `Host` header,
   and HTTP proxy credential headers such as `Proxy-Authorization`.
1. Read the request body up to the configured maximum.
1. Compute the request body byte count and digest.
1. Build the upstream URL from the configured origin plus accepted path and
   query.
1. Build an upstream request carrying the configured timeout deadline.
1. Send the upstream request; the adapter applies the carried deadline.
1. Stream the upstream response to the harness while counting bytes and
   updating the response digest.
1. Write a required audit event before the request task is considered
   complete.

If a request is denied before upstream I/O, the gateway writes a denied audit
event and returns an HTTP error without contacting the provider.

Requests that hyper cannot parse, such as malformed request lines or
scheme-without-authority request targets, are rejected with an HTTP 400
before the handler runs and produce no audit event. Every request that
reaches the gateway's decision path is audited.

If a bound is exceeded before response streaming starts, the gateway writes a
denied or failure audit event and returns a typed HTTP error. If a bound is
exceeded after response streaming starts, the gateway terminates the stream,
writes a `response_error` audit event, and fails closed.

If a required audit event cannot be written before a response to the harness
has started, the gateway returns an HTTP 500 instead of an unaudited harness
response. If the failure is detected before upstream I/O, the provider is not
contacted. If the failure is detected after upstream I/O has already occurred,
such as while auditing an upstream response-header failure, the provider
request cannot be undone but the harness still receives only the HTTP 500.
If a required audit event cannot be written after an upstream response has
started, including after the upstream response body has been fully forwarded,
the gateway exits the process with a non-zero status so the container fails
closed and the request cannot complete as an unaudited success.

## 11. Audit Log

The audit log is newline-delimited JSON.

The event schema is:

```json
{
  "version": 3,
  "timestamp": "2026-07-01T00:00:00.000000000Z",
  "request_id": "req-<run>-<sequence>",
  "decision": "allowed",
  "method": "POST",
  "path": "/v1/responses",
  "query": null,
  "upstream_origin": "https://api.openai.com",
  "upstream_path": "/v1/responses",
  "upstream_query": null,
  "status": 200,
  "request_body": {
    "state": "non_empty",
    "bytes": 1234,
    "blake3": "hex..."
  },
  "response_body": {
    "state": "non_empty",
    "bytes": 5678,
    "blake3": "hex..."
  },
  "error_class": null
}
```

`decision` is a closed string set:

- `allowed`;
- `denied`;
- `upstream_error`;
- `response_error`.

Invalid startup configuration stops the gateway before it accepts traffic,
so no configuration decision ever appears in the request audit stream.

The example's field order is illustrative; events serialize a fixed field
set without a guaranteed key order. `timestamp` is RFC 3339 UTC with
nanosecond precision. `request_id` embeds a per-process run token and a
monotonic sequence, so identities from different gateway runs appended to
the same audit log do not collide.

`path` is the accepted request path. For denied non-origin-form requests it
records the full raw request target, including the requested authority, such
as `http://evil.example/steal` or `evil.example:443`.
`upstream_path` and `upstream_query` are null when no upstream request is
attempted. When an upstream request is attempted, `upstream_query` equals the
accepted incoming query. `status` is the response status returned to the
harness. Every decision records one: each closed audit outcome variant
carries a mandatory status. The serialized `status` field is structurally
nullable but always populated.
`request_body` and `response_body` are closed body-summary objects. Their
`state` is one of `not_observed`, `empty`, or `non_empty`. `not_observed`
means the gateway could not summarize body bytes on that path. `empty` means
the gateway observed an empty body. `non_empty` includes `bytes` and `blake3`
fields, where `bytes` is non-zero and `blake3` is the lowercase BLAKE3 hex
digest of the observed bytes.

An audit write failure cannot be represented as an `audit_error` event in the
required audit log because the failure mode is the inability to write that log.
The process fails closed instead.

Request and response header values MUST NOT be logged. If header logging is
added later, authorization and cookie-like headers, including `Authorization`,
`Proxy-Authorization`, `Cookie`, `x-api-key`, and provider-specific credential
headers, MUST be redacted by default.

Request and response bodies are not logged by default. Body digests and byte
counts are logged.

## 12. Container Images

The Dockerfile has these named stages:

- `proxy-builder`: Rust build stage based on `rust:1-trixie`.
- `proxy`: scratch runtime image for `custode-proxy`.
- `harness`: Debian `trixie-slim` runtime image for the untrusted harness.

The `proxy-builder` stage installs only the packages needed to produce the
static binary and then builds `custode-proxy` for the build platform's native
musl target.

The `proxy` stage contains only:

- `/custode-proxy`;
- CA certificates required for upstream TLS;
- required metadata files if numeric user execution needs them;
- pre-created, gateway-owned mount points for the audit log volume and the
  `/tmp` tmpfs, which a read-only root filesystem cannot create at runtime.

The `proxy` stage runs as `65532:65532`, exposes port `8080`, and has a
Dockerfile healthcheck that calls the proxy binary's healthcheck subcommand.
The subcommand opens a TCP connection to the gateway socket from inside the
container and succeeds when the listener accepts. The probe adds no provider
path, sends no HTTP request, never reaches the upstream, and produces no
request audit event. The probe targets the default bind port, so an operator
override of the `CUSTODE_BIND` port requires a matching healthcheck override.
The harness can already reach the gateway socket by design, so the probe
exposes no surface the internal network does not already have.

The `harness` stage contains Debian `trixie-slim`, CA certificates, `bash`,
`git`, `curl`, and minimal process and network utilities (`procps`,
`iproute2`) needed by common harnesses and by containment diagnostics.
Containment does not depend on the absence of tools in the untrusted
container; network isolation is enforced by the Compose topology. It
does not install any specific harness by default.

The `harness` stage accepts `HARNESS_NPM_PACKAGES` as a build argument. The
Compose file maps the operator environment variable
`CUSTODE_HARNESS_NPM_PACKAGES` to this build argument. When the argument is
non-empty, the stage installs Node.js and npm and installs the supplied npm
packages into `/opt/harness/npm`. This lets the operator build a harness image
with tools such as Claude Code without hard-coding a specific harness into the
Dockerfile.

The `harness` stage runs as `1000:1000`, uses `/workspace` as the workdir, and
has a simple healthcheck that proves the workspace path exists.

## 13. Compose Topology

The Compose file defines two services:

- `proxy`, built from the `proxy` target;
- `harness`, built from the `harness` target.

The Compose file defines two networks:

```yaml
networks:
  internal:
    internal: true
  egress: {}
```

The `harness` service is attached only to `internal`.

The `proxy` service is attached to `internal` and `egress`.

The `harness` service depends on the `proxy` service healthcheck.

The `harness` service mounts the operator workspace at `/workspace`.

The checked-in Compose file passes `CUSTODE_UPSTREAM_ORIGIN` and
`CUSTODE_ALLOWED_OPERATIONS` through from the operator environment with empty
defaults, so an unconfigured gateway fails closed at startup instead of
running with an implicit provider surface.

The checked-in `harness` service environment contains only explicit base URL
defaults and one explicit harness environment file. The file defaults to
`./secrets/env.example`; operators can set `CUSTODE_HARNESS_ENV_FILE` to point
at a real ignored harness-local environment file such as `./secrets/env`.

The harness environment file is also mounted read-only at `/etc/environment`
for harnesses and operators that inspect that path. Compose `env_file` is what
loads the values into the harness process environment; the mount alone does
not make shell commands inherit the values.

The `harness` service MUST NOT import the host environment wholesale through
bare variable interpolation or unscoped environment pass-through. Values in
the harness environment file are readable by the untrusted harness. Provider
credentials that the harness needs MAY be placed there. Docker credentials,
host API tokens, and broad host ambient secrets MUST NOT be placed there
unless the operator intentionally wants the harness to read them.

The `proxy` service mounts an audit log volume at `/var/log/custode`. It does
not mount provider credentials.

The `proxy` service does not publish port `8080` to the host by default. The
gateway is for the harness container, not for host traffic.

## 14. Runtime Hardening

Both services use:

- `cap_drop: ["ALL"]`;
- `security_opt: ["no-new-privileges:true"]`;
- `init: true`;
- `pids_limit`;
- memory limits where supported by the Compose implementation.

The `proxy` service uses:

- `read_only: true`;
- tmpfs for `/tmp`;
- writable audit log volume only at `/var/log/custode`;
- no workspace mount;
- no shell in the runtime image.

The `harness` service uses:

- no Docker socket mount;
- no host network;
- no privileged mode;
- a read-only root filesystem when the selected harness can tolerate it;
- tmpfs for mutable runtime paths;
- explicit workspace mount as the only durable write surface.

## 15. Harness Contract

The harness command is supplied by the operator through Compose override,
`CUSTODE_HARNESS_COMMAND`, `docker compose run`, or an explicit command in the
checked-in Compose file.

Harness-specific environment variables are supplied through the file named by
`CUSTODE_HARNESS_ENV_FILE`. The default points at `./secrets/env.example`.
Operators SHOULD copy it to `./secrets/env`, edit that ignored file, and run
Compose with `CUSTODE_HARNESS_ENV_FILE=./secrets/env`.

The operator can build a Claude Code harness without changing the Dockerfile:

```sh
CUSTODE_HARNESS_NPM_PACKAGES='@anthropic-ai/claude-code' docker compose build harness
```

The operator can run that harness by setting the runtime command:

```sh
CUSTODE_HARNESS_COMMAND='claude --version' docker compose run --rm harness
```

The harness MUST be configured to send provider API requests to
`http://proxy:8080`. A different service name is allowed only in an operator
Compose override that also renames the gateway service and keeps the harness
attached only to the same internal network.

For OpenAI-compatible clients, the expected non-secret setting is:

```text
OPENAI_BASE_URL=http://proxy:8080
```

For Anthropic-compatible clients, the expected non-secret setting is:

```text
ANTHROPIC_BASE_URL=http://proxy:8080
```

Anthropic API-key mode uses `ANTHROPIC_API_KEY` in the harness environment.
The operator should configure the upstream and allowlist with:

```text
CUSTODE_UPSTREAM_ORIGIN=https://api.anthropic.com
CUSTODE_ALLOWED_OPERATIONS=POST:prefix:/v1/messages,GET:prefix:/v1/models
```

Claude Code may require `ANTHROPIC_API_KEY` in the harness environment so the
client chooses API-key mode. That value belongs in the harness environment
file. The gateway forwards the resulting provider request headers without
knowing which ones carry credentials.

The operator can run a non-interactive Claude Code prompt through the gateway:

```sh
CUSTODE_HARNESS_NPM_PACKAGES='@anthropic-ai/claude-code' \
CUSTODE_UPSTREAM_ORIGIN=https://api.anthropic.com \
CUSTODE_ALLOWED_OPERATIONS='POST:prefix:/v1/messages,GET:prefix:/v1/models' \
CUSTODE_HARNESS_ENV_FILE=./secrets/env \
CUSTODE_HARNESS_COMMAND='claude --bare -p "what is 2+2?" \
--output-format text --max-budget-usd 0.01' \
docker compose up --abort-on-container-exit --exit-code-from harness
```

The provider API key in `./secrets/env` is visible to the harness by design.
Custode constrains where the harness can send HTTP, not how the harness
authenticates to the provider.

Harnesses that cannot set a provider base URL are not compatible with the
initial architecture.

## 16. Testing Architecture

Unit tests live inline in each source file's `tests` module and cover:

- configuration parsing, including the fail-closed rejections: empty
  allowlists, unknown operation kinds, invalid methods, wildcard hosts,
  origin credentials, and zero bounds;
- operation allowlist decisions, proving each decision binds one method to one
  exact path or segment-bounded path prefix with no method and path
  cross-product;
- upstream URL construction;
- hop-by-hop header stripping;
- provider authorization header pass-through;
- audit event serialization, including the closed decision set, the full
  field set, and null semantics;
- timestamp formatting at calendar boundary instants;
- adapter classification of Reqwest errors against real local sockets:
  connection refusal, timeout, protocol garbage, and body-stream failure;
- the deterministic handler with injected ports (fixed clock, in-memory
  audit sink, scripted upstream client), run on a paused current-thread Tokio
  runtime and asserting exact full audit events for success and timeout paths.

Property-based tests normally live inline in each source file's `proptests`
module and cover the parsers, constructors, and serializers with paired
accept-every-valid and reject-every-invalid grammars: allowed operation
parsing, upstream origin parsing, segment-bounded prefix matching, upstream
URL joining, accepted-target validation (dot segments, percent encoding,
origin form), header filtering (hop-by-hop stripping, byte limits,
connection tokens), upstream request construction from allowed targets
(`UpstreamRequest::from_target`), audit event serialization option
semantics, request identity formatting, and timestamp round-tripping.
Generated gateway scenario property tests live inside `http`'s inline
`tests::proptests` module because their oracle intentionally reuses the
test-only HTTP scenario runner helpers rather than publishing those helpers
as a wider crate test-support surface.

Simulation tests are test-only and live behind `#[cfg(test)]`. They run the
real Axum handler on a paused current-thread Tokio runtime, with the
production adapters replaced by deterministic ports from `src/sim.rs`:
`FixedClock`, `MemoryAuditSink`, `ScriptedUpstreamClient`, and generated
`Scenario` values. The current request grammar covers allowed `GET`
`/v1/models` requests with bounded generated bodies, generated query strings,
and generated header sets over both forwarded and stripped header names. The
current fault grammar covers saturated admission permits, audit write failure
on the terminal event, provider success, virtual-time upstream stalls past the
carried deadline, upstream response stream failure after a body chunk, and
response byte bounds smaller than the scripted response. A deterministic class
sweep covers the full 24-element product of admission, audit, response-bound,
and upstream-outcome classes every run, plus the two reachable downstream
disconnect classes for a successful streamed response; the property test then
randomizes request dimensions inside those classes. The oracle asserts
invariants over each scenario class: response status and stream outcome,
fatal-channel behavior after response start, upstream request presence,
forwarded-header safety, response byte bounds, and the 14-field audit event
schema and closed decision set when auditing succeeds. Simulation tests use
Tokio's paused virtual clock and MUST NOT use wall-clock sleeps; real-time
sleeps are confined to real-socket tests that exercise Hyper, Reqwest, and
integration timing. Simulation tests do not replace the real hyper
parse-boundary tests, real Reqwest socket-classification tests, or container
network-isolation tests.

Integration tests in `tests/gateway.rs` run the compiled `custode-proxy`
binary against a local recording upstream and cover:

- allowed request reaches a local test upstream;
- allowed request reaches only the configured upstream origin, with the
  incoming `Host` header unable to redirect it;
- denied method does not reach a local test upstream;
- denied path does not reach a local test upstream;
- raw absolute-form, authority-form, and `CONNECT` request lines are denied
  without reaching a local test upstream and audited with the raw
  authority-bearing target;
- harness-supplied authorization reaches the local test upstream for allowed
  requests;
- every allowed and denied request produces an audit event with a unique
  request identity;
- an unopenable audit log fails closed at startup;
- a missing allowlist fails closed at startup;
- a wildcard upstream origin fails closed at startup.

Container tests are implemented by `scripts/container-test.sh`, run with
`just docker-test`, and cover:

- `docker compose build proxy harness`;
- static linkage of `/custode-proxy` in the `proxy` image;
- `docker compose up --detach --wait` with a healthy proxy;
- the proxy publishes no ports to the host, so the gateway and its
  healthcheck are reachable only from the Compose networks;
- harness cannot reach an external URL directly;
- harness reaches the gateway service on the internal network.

The direct-egress denial test MUST run from inside the harness container. A
passing proxy request is not proof that direct egress is denied.

Mutation runs that gate a change are scoped to the touched files with unit
tests only (`cargo mutants -f <file> -- --lib`); the `just mutants` recipe
runs the full unscoped suite. Surviving mutants are either killed with new
unit tests or documented as equivalent at the mutation site.

## 17. Initial Build Plan

The initial build sequence is:

1. Write [IDEA.md](IDEA.md) from the containment idea.
1. Derive this architecture from [IDEA.md](IDEA.md).
1. Review both documents in alternating order until suggestions stop,
   quality degrades, or scope expands.
1. Add the Rust project setup.
1. Implement configuration parsing and pure allowlist decisions.
1. Implement audit event serialization and fail-closed audit writer.
1. Implement the HTTP gateway.
1. Add the multi-stage Dockerfile.
1. Add Compose topology and hardening.
1. Prove the direct-egress denial and gateway allow/deny behavior.

## 18. Reliability and Security Considerations

Compose network isolation is the core containment mechanism. Any change that
attaches the harness service to an egress-capable network changes the trust
model and requires revising [IDEA.md](IDEA.md).

The gateway cannot inspect traffic that bypasses its provider-shaped HTTP
contract. `CONNECT`, WebSockets, raw TCP, and DNS forwarding are therefore
denied instead of partially supported.

The gateway does not own provider credentials. Authentication is harness-local
provider configuration. This avoids coupling Custode to every provider's auth
scheme and keeps the proxy focused on egress control, allowlisting, and audit.

The audit log is useful only if it is complete. The gateway fails closed on log
write errors even though that can reduce availability.

## 19. Open Issues

- Whether to add first-class provider profiles for OpenAI, Anthropic, and other
  APIs instead of operator-provided path allowlists.
- Whether the harness image should eventually split into named variants for
  Codex, Claude Code, or other harnesses.
- Whether multi-architecture static builds should be supported in the first
  release or kept behind explicit build arguments.

## 20. References

### 20.1. Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174, May 2017.

### 20.2. Informative References

- [RFC7322] Flanagan, H. and S. Ginoza, "RFC Style Guide", RFC 7322,
  September 2014.
- [RFC2026] Bradner, S., "The Internet Standards Process -- Revision 3",
  BCP 9, RFC 2026, October 1996.
