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
- Toolchain: pinned per commit via `rust-toolchain.toml`, following the
  sibling `incremental-gate` setup.
- Async runtime: Tokio.
- HTTP server: Hyper through Axum.
- HTTP client: Reqwest with Rustls TLS and no native TLS dependency.
- URL representation: `url::Url`.
- Serialization: Serde and `serde_json`.
- Request digest: BLAKE3.
- CLI parsing: Clap.
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

The local gate vocabulary follows `incremental-gate`:

- `just fmt-check` runs `cargo fmt --all --check`.
- `just lint` runs Clippy for all targets and all features.
- `just test` runs the Rust test suite.
- `just docs` runs Markdown linting when `mado` is available.
- `just deny` runs `cargo deny check` when `cargo-deny` is available.
- `just check` runs formatting, linting, tests, and Dockerfile syntax checks.

Rust lint posture follows `incremental-gate`: warnings, missing docs, unsafe
code, future incompatibilities, unused dependencies, and broad Clippy lint
groups are denied. Suppressions MUST NOT be used to hide warnings. If a
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
├── .cargo/
│   ├── config.toml
│   ├── clippy.toml
│   └── deny.toml
├── docs/
│   ├── IDEA.md
│   └── ARCHITECTURE.md
└── src/
    ├── lib.rs
    └── main.rs
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
src/config.rs          Gateway configuration and fail-closed parsing
src/allowlist.rs       Method and path decision logic
src/audit.rs           Audit event schema and writer
src/gateway.rs         Request handling state machine
src/http.rs            Axum and Reqwest runtime edges
src/headers.rs         Hop-by-hop and redaction rules
src/body.rs            Bounded body accounting and BLAKE3 digests
src/health.rs          Healthcheck command and endpoint
src/error.rs           Error model and HTTP status mapping
```

These module names SHOULD remain stable through the initial product. A module
name MAY change only when the old name would become misleading after a
contraction of scope. A rename MUST preserve the ownership boundaries in this
section and the dependency direction in Section 7.

## 7. Dependency Direction

The library dependency direction is:

- `config` depends on primitive parsing, `url::Url`, and typed config errors.
- `allowlist` depends on `config` types and owns pure allow/deny decisions.
- `body` owns byte limits and digest accounting.
- `headers` owns header filtering and redaction rules.
- `audit` depends on typed request and response summaries, not on the HTTP
  server runtime.
- `gateway` depends on `config`, `allowlist`, `body`, `headers`, and `audit`.
- `http` depends on `gateway` and owns Axum/Reqwest conversions.
- `main` depends on the library and owns process startup.

Pure decision modules MUST NOT depend on Axum, Reqwest, Tokio sockets, process
environment access, or filesystem mutation. Runtime modules adapt those pure
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
- absolute-form targets such as `https://api.openai.com/v1/responses`;
- paths that do not start with `/`;
- paths containing invalid percent-encoding;
- methods absent from the configured method allowlist;
- paths absent from the configured exact path or path-prefix allowlist.

The gateway constructs the upstream URL by joining the configured provider
origin with the accepted path and query. The incoming `Host` header does not
select the upstream host.

The initial protocol surface is HTTP request and response forwarding with
streaming response support. WebSockets, arbitrary TCP, UDP, DNS forwarding, and
HTTP `CONNECT` are not part of the gateway protocol.

## 9. Gateway Configuration

The initial gateway configuration comes from environment variables:

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

Configuration parsing is fail-closed:

- `CUSTODE_BIND` MUST parse as a socket address.
- `CUSTODE_UPSTREAM_ORIGIN` MUST parse as an HTTP or HTTPS URL with scheme,
  host, and optional port, and MUST NOT include path, query, or fragment.
- `CUSTODE_ALLOWED_OPERATIONS` MUST contain at least one operation.
- Each operation MUST have the form `METHOD:exact:/path` or
  `METHOD:prefix:/path`.
- Every configured path or prefix MUST begin with `/`.
- Prefix matching MUST be segment-bounded: `/v1/responses` matches
  `/v1/responses` and `/v1/responses/{id}`, but not `/v1/responses-other`.
- Request paths MUST NOT contain literal or percent-encoded `.` or `..`
  segments, because the allowlist and upstream URL builder MUST operate on the
  same path representation.
- Size, concurrency, and duration bounds MUST be positive.

A later file-based config MAY replace environment parsing, but it MUST keep the
same fail-closed semantics.

## 10. Gateway Runtime Flow

For each request, the gateway performs these steps in order:

1. Allocate a request identity.
1. Parse and validate the method and origin-form target, rejecting literal or
   percent-encoded dot segments.
1. Check the method-path operation allowlist.
1. Copy end-to-end headers, excluding hop-by-hop headers and `Host`.
1. Read the request body up to the configured maximum.
1. Compute the request body byte count and digest.
1. Build the upstream URL from the configured origin plus accepted path and
   query.
1. Send the upstream request with the configured timeout.
1. Stream the upstream response to the harness while counting bytes and
   updating the response digest.
1. Write a required audit event before the request task is considered
   complete.

If a request is denied before upstream I/O, the gateway writes a denied audit
event and returns an HTTP error without contacting the provider.

If the audit event cannot be written before a response has started, the gateway
returns an HTTP 500. If the audit event cannot be written after an upstream
response has started, including after the upstream response body has been fully
forwarded, the gateway exits the process with a non-zero status so the
container fails closed.

## 11. Audit Log

The audit log is newline-delimited JSON.

The event schema is:

```json
{
  "version": 1,
  "timestamp": "2026-07-01T00:00:00Z",
  "request_id": "01J...",
  "decision": "allowed",
  "method": "POST",
  "path": "/v1/responses",
  "query": null,
  "upstream_origin": "https://api.openai.com",
  "upstream_path": "/v1/responses",
  "upstream_query": null,
  "status": 200,
  "request_bytes": 1234,
  "response_bytes": 5678,
  "request_body_blake3": "hex...",
  "response_body_blake3": "hex...",
  "error_class": null
}
```

`decision` is a closed string set:

- `allowed`;
- `denied`;
- `upstream_error`;
- `response_error`;
- `configuration_error`.

An audit write failure cannot be represented as an `audit_error` event in the
required audit log because the failure mode is the inability to write that log.
The process fails closed instead.

Authorization, cookie, and proxy authorization header values MUST NOT be
logged.

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
- required metadata files if numeric user execution needs them.

The `proxy` stage runs as `65532:65532`, exposes port `8080`, and has a
Dockerfile healthcheck that calls the proxy binary's healthcheck subcommand.

The `harness` stage contains Debian `trixie-slim`, CA certificates, `bash`,
`git`, `curl`, and minimal process utilities needed by common harnesses. It
does not install any specific harness by default.

The `harness` stage accepts `HARNESS_NPM_PACKAGES` as a build argument. When it
is non-empty, the stage installs Node.js and npm and installs the supplied npm
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
credentials that the harness needs MAY be placed there. Docker credentials and
broad host ambient secrets MUST NOT be placed there unless the operator
intentionally wants the harness to read them.

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

Unit tests cover:

- configuration parsing;
- method allowlist decisions;
- path exact-match and prefix-match decisions;
- upstream URL construction;
- hop-by-hop header stripping;
- provider authorization header pass-through;
- audit event serialization.

Integration tests cover:

- allowed request reaches a local test upstream;
- allowed request reaches only the configured upstream origin;
- denied method does not reach a local test upstream;
- denied path does not reach a local test upstream;
- harness-supplied authorization reaches the local test upstream for allowed
  requests;
- every allowed and denied request produces an audit event;
- audit log write failure fails closed.

Container tests cover:

- `docker compose build proxy harness`;
- static linkage of `/custode-proxy` in the `proxy` image;
- `docker compose up --detach --build`;
- successful proxy healthcheck;
- proxy healthcheck is container-local and does not expose a provider-shaped
  gateway path to the harness;
- harness cannot reach an external URL directly.

The direct-egress denial test MUST run from inside the harness container. A
passing proxy request is not proof that direct egress is denied.

## 17. Initial Build Plan

The initial build sequence is:

1. Write [IDEA.md](IDEA.md) from the containment idea.
1. Derive this architecture from [IDEA.md](IDEA.md).
1. Review both documents in alternating order until suggestions stop,
   quality degrades, or scope expands.
1. Add the Rust project setup from `../incremental-gate/`.
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
