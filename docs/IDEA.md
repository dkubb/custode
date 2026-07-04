# Custode Contained Harness Gateway Idea Requirements

Status of This Memo

This document is an internal project specification written in an RFC-style
Markdown form. The document borrows structure and editorial discipline from
RFC 7322 and uses RFC 2026 as process vocabulary for maturity, review, and
applicability.

This document is authoritative for the Custode project. When this document
conflicts with any other project artifact, this document takes precedence for
goals, scope, non-goals, and invariants. The companion
[ARCHITECTURE.md](ARCHITECTURE.md) document is authoritative for concrete
architecture and technology choices only when those choices preserve this
document's requirements.

Abstract

This document defines the goals, scope, trust model, non-goals, and invariants
for running an untrusted agent harness inside Docker with no direct host
environment access and no direct internet egress. The harness container can
edit only explicitly mounted files and can reach the outside world only through
a separate Rust provider gateway container. The gateway container is the only
container with external network egress, allows only configured provider API
requests, and writes structured request logs for offline review. This document
intentionally avoids concrete implementation choices except where they are
necessary to state the required isolation and audit properties.

Table of Contents

- [Section 1: Introduction](#1-introduction)
- [Section 2: Requirements Language](#2-requirements-language)
- [Section 3: Scope and Trust Model](#3-scope-and-trust-model)
- [Section 4: Product Model](#4-product-model)
- [Section 5: Normative Requirements](#5-normative-requirements)
- [Section 6: Non-Goals](#6-non-goals)
- [Section 7: Reliability and Security Considerations](#7-reliability-and-security-considerations)
- [Section 8: References](#8-references)

## 1. Introduction

Agent harnesses such as Claude Code, Codex, or similar systems are powerful
enough that they should be treated as untrusted when they are asked to execute
commands, inspect files, or call external model providers. A harness that runs
directly on the host can read ambient environment variables, discover local
credentials, open arbitrary network connections, and hide its behavior among
ordinary host processes.

Custode exists to make that runtime boundary explicit. The harness runs in one
container. A small Rust gateway runs in a second container. The harness
container is attached only to an internal Docker network. The gateway container
is attached to that internal network and to an egress network. The gateway is
the only process that can reach the provider.

The proxy is intentionally not a general-purpose forward proxy. A generic
`HTTPS_PROXY` tunnel cannot inspect the provider API path without terminating
TLS, and terminating arbitrary provider TLS would add certificate authority,
trust-store, and man-in-the-middle complexity. Custode instead starts with an
explicit provider gateway: the harness MUST be configured to send provider API
requests to the gateway as its provider base URL. The gateway then sends the
allowed request to the real provider.

The kernel is this: the harness may be malicious, confused, or compromised; it
still receives only an internal network, explicitly mounted files, and a
provider-shaped gateway that logs and denies by default.

## 2. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here.

Lowercase uses of these words have their ordinary English meanings.

## 3. Scope and Trust Model

Custode is a local, single-operator containment system for running one
untrusted harness process tree at a time.

The harness container is untrusted. Any process inside the harness container
MUST be assumed able to read the harness container filesystem, modify mounted
workspace files according to mount permissions, inspect the harness container
environment, and make arbitrary network requests to any address reachable from
the harness container network namespace.

The provider gateway is trusted but intentionally small. The gateway is part of
the trusted computing base because it enforces the provider allowlist, bounds
traffic, controls upstream egress, and writes the audit log.

The host kernel, Docker daemon, container runtime, Docker network isolation,
and configured provider are part of the trusted computing base. Custode does
not claim to contain a real container escape, kernel exploit, compromised
Docker daemon, or malicious provider.

Network isolation MUST be enforced by container networking, not by asking the
harness to respect environment variables. Provider base URL environment
variables MAY be provided for harness compatibility, but they MUST point at the
gateway and MUST NOT be the enforcement boundary.

Harness-specific credentials MAY be mounted into the harness container when
the operator intentionally wants the harness to use them. Credential secrecy is
not the primary boundary. The primary boundary is that the harness cannot send
network traffic except through inspectable gateway requests.

The initial product supports harnesses that can be configured with a provider
base URL pointing at the gateway. Harnesses that require direct TLS to the
provider and cannot use a gateway base URL are outside the initial scope.

## 4. Product Model

The product model contains these concepts:

- host;
- Docker daemon;
- Compose project;
- harness image;
- harness container;
- harness process tree;
- mounted workspace;
- provider gateway image;
- provider gateway container;
- internal network;
- egress network;
- provider;
- provider base URL;
- upstream origin;
- gateway request;
- upstream request;
- allowed API operation;
- denied request;
- provider credential;
- request identity;
- audit log;
- audit event;
- request body digest;
- response body digest;
- log sink;
- healthcheck;
- static proxy binary;
- scratch runtime image;
- container capability set;
- resource limit;
- read-only root filesystem;
- tmpfs scratch path.

The model intentionally distinguishes:

- network containment, which is enforced by Docker networks;
- provider authorization, which is emitted by the harness and forwarded as
  end-to-end HTTP request data;
- provider authentication, which is owned by the harness/provider SDK
  configuration;
- file mutation, which is controlled by explicit volume mounts;
- request observation, which is recorded by gateway audit events.

The model intentionally has one provider gateway instance per provider
configuration. A later system MAY run multiple gateway instances, but each
instance still has exactly one configured upstream origin and one configured
allowlist.

## 5. Normative Requirements

### 5.1. Two-Container Boundary

Custode MUST run the harness and provider gateway as separate containers.

The harness container MUST NOT share the provider gateway process namespace,
filesystem root, writable layers, Docker socket, host network namespace, host
PID namespace, host IPC namespace, or host credentials.

The provider gateway container MUST NOT mount the workspace volume. The gateway
has no need to read or write the files the harness is editing.

The harness container MAY mount an operator-selected workspace volume. That
mount MUST be explicit. The default composition SHOULD mount a single workspace
path at a predictable path inside the harness container.

Both containers MUST run as non-root users, drop Linux capabilities, and set
`no-new-privileges`. The provider gateway container MUST use a read-only root
filesystem. The harness container SHOULD use a read-only root filesystem when
compatible with the selected harness.

Both containers SHOULD set explicit process count and memory limits.

The default composition SHOULD start the harness container only after the
provider gateway container reports healthy.

### 5.2. Network Authority

The harness container MUST be attached only to an internal network that has no
external egress route.

The provider gateway container MUST be attached to the internal network and to
an egress-capable network.

The harness container MUST reach the provider gateway through the internal
network service name. The harness container MUST NOT be able to open direct TCP
connections to the provider, public DNS resolvers, package registries, telemetry
collectors, or arbitrary internet hosts through its own network namespace.

The provider gateway MUST be the only service in the Compose project that can
open external provider connections.

### 5.3. Provider Gateway Contract

The gateway MUST be a provider-shaped HTTP gateway, not a general-purpose
forward proxy.

The gateway MUST reject HTTP `CONNECT` requests.

The gateway MUST reject absolute-form request targets. Incoming request targets
MUST use origin-form paths such as `/v1/responses`, MUST begin with `/`, and
MUST NOT contain invalid percent-encoding. Incoming request paths MUST NOT
contain literal query delimiters, literal fragment delimiters, literal
backslashes, percent-encoded path separators, or literal or percent-encoded `.`
or `..` segments, so that the allowlist decision and the upstream URL are
computed from the same path segment structure. Incoming request queries MUST NOT
contain literal fragment delimiters.

The gateway MUST derive the upstream URL by joining the configured provider
origin with the incoming origin-form path and query. The incoming `Host` header
MUST NOT select, override, or influence the upstream origin.

The gateway MUST allow only configured API operations. Each allowed operation
MUST bind exactly one HTTP method to exactly one exact path or segment-bounded
path prefix. Separate global method and path lists are invalid because they
create an unintended Cartesian product. The allowlist MUST be explicit. A
missing or invalid allowlist MUST fail closed.

The gateway MUST allow exactly one configured upstream scheme, host, and port
per gateway instance. Wildcard provider hosts are invalid.

The gateway MUST strip hop-by-hop headers before sending an upstream request.
The gateway MUST strip the incoming `Host` header and HTTP proxy credentials
before sending an upstream request.

The gateway MUST forward end-to-end provider request headers without knowing
which headers are credentials. This includes provider-specific authorization
headers such as `Authorization`, `x-api-key`, `Cookie`, or custom headers. The
gateway MUST NOT synthesize provider authentication headers in the initial
product.

The gateway MUST preserve streaming responses well enough for model clients
that use server-sent events or chunked response bodies.

### 5.4. Harness Environment Boundary

The default composition MAY load one explicit operator-selected harness
environment file. Every value in that file MUST be treated as readable by the
untrusted harness.

The default Compose file MUST NOT pass host environment variables wholesale
into the harness container.

The harness container MAY receive provider credentials and provider base URL
configuration through the harness environment file. The provider base URLs MUST
point at the gateway. Docker credentials, host API tokens, and broad host
ambient secrets MUST NOT be placed in the harness environment file unless the
operator intentionally wants the harness to read them.

The audit log MUST NOT include provider credential header values. If request
header logging is added later, authorization and cookie-like headers MUST be
redacted by default.

### 5.5. Audit Logging

The gateway MUST write one structured audit event for every runtime request
decision: allowed upstream request, denied request, upstream failure, or
response completion failure. Invalid startup
configuration MUST stop the gateway before it accepts traffic and does not need
a request audit event. Local healthcheck requests answered by the gateway
itself are not runtime request decisions and do not require request audit
events. Requests the HTTP implementation rejects before they parse into a
request are outside the runtime decision path; they MUST be refused without
forwarding, and MAY be surfaced through connection-level diagnostics rather
than request audit events.

If the gateway cannot allocate a request identity, it MUST fail closed by
terminating the gateway. No request audit event is possible on that path
because the audit schema requires the missing request identity.

Each audit event MUST include:

- schema version;
- timestamp;
- request identity;
- decision;
- method;
- incoming path and query;
- configured upstream origin;
- upstream path and query when an upstream request is attempted, where the
  upstream query records the query from the joined upstream URL and MAY differ
  from the accepted incoming query only by URL serialization;
- response status when one exists;
- request body summary with one of three states: not observed, observed empty,
  or observed non-empty with byte count and body digest;
- response body summary with one of three states: not observed, observed empty,
  or observed non-empty with byte count and body digest;
- error class when a request fails before normal completion.

Audit events MUST be newline-delimited JSON.

The gateway MUST fail closed if it cannot write a required audit event.
Failing closed means the affected request MUST NOT complete as an unaudited
success: before a response starts, the gateway MUST return an error without
forwarding; after a response has started, the gateway MUST terminate so that
unaudited traffic cannot continue.

Raw request and response body capture is OPTIONAL and MUST be separately
configured with bounded sizes. Body capture MUST NOT be required for the
initial product.

### 5.6. Filesystem Boundary

The harness container MUST have no implicit access to the host filesystem.

The harness container MUST write only to explicit workspace and scratch mounts.
The default root filesystem SHOULD be read-only, with tmpfs mounts for runtime
paths that need mutation.

The provider gateway container MUST write only to its audit log sink and tmpfs
runtime paths.

The provider gateway container MUST NOT expose a shell in the runtime image.

### 5.7. Build and Runtime Image Requirements

The provider gateway MUST be implemented in Rust.

The gateway runtime image MUST be `scratch` for the initial product.

The gateway binary MUST be statically linked.

The gateway build stage SHOULD use the same Linux distribution family as the
harness runtime image. If the harness runtime uses Debian, the gateway builder
SHOULD also be Debian-based.

The harness runtime image MUST be a modern Linux distribution with a clear
security update process. The selected distribution MUST be recorded in
[ARCHITECTURE.md](ARCHITECTURE.md).

Base images SHOULD be pinned by digest.

### 5.8. Configuration

Gateway configuration MUST be explicit and inspectable.

Gateway configuration MUST include:

- bind address;
- upstream provider origin;
- allowed API operations, each binding one method to one exact path or
  segment-bounded path prefix;
- log sink;
- request timeout;
- maximum request header bytes;
- maximum request body bytes;
- maximum response header bytes;
- maximum response bytes forwarded or read before aborting;
- maximum concurrent requests;
- maximum audit event size.

Invalid configuration MUST stop the gateway before it accepts traffic.

The upstream provider origin MUST be a scheme, host, and optional non-zero port
only. Path, query, fragment, and wildcard hosts are invalid.

The harness command is intentionally operator-supplied. Custode MUST NOT try to
hide which harness command is being run.

### 5.9. Bounded State

The gateway MUST bound:

- allowed operation count and operation text bytes;
- incoming path bytes;
- incoming query bytes;
- request header bytes;
- request body bytes;
- response header bytes;
- response body bytes read before aborting;
- request duration;
- concurrent requests;
- audit event size.

When a bound is exceeded before response streaming starts, the gateway MUST
write a denial or failure audit event and return a typed HTTP error. When a
bound is exceeded after response streaming starts, the gateway MUST terminate
the stream and fail closed.

### 5.10. Testability

Custode MUST include tests that prove:

- denied methods do not reach the upstream provider;
- denied paths do not reach the upstream provider;
- allowed requests reach only the configured upstream provider;
- provider authorization headers supplied by the harness reach only allowed
  upstream requests;
- every allowed and denied request produces an audit event;
- audit log write failure fails closed;
- the gateway binary used in the scratch image is statically linked;
- the Compose topology leaves the harness without direct external egress.

## 6. Non-Goals

Custode does not attempt to prevent Docker escapes, kernel exploits, malicious
Docker daemon behavior, or attacks by a compromised host.

Custode does not attempt to make an untrusted provider safe. Data sent to the
provider is visible to that provider.

Custode does not provide a general-purpose anonymous browsing environment.

Custode does not implement TLS man-in-the-middle interception in the initial
product.

Custode does not support `HTTPS_PROXY` or `CONNECT` tunneling in the initial
product.

Custode does not install Claude, Codex, or any specific harness by default.
The operator supplies the harness command and any required harness-local
configuration.

Custode does not provide full data-loss prevention. It narrows and records the
network path; it does not prove that provider-bound content is safe to send.

## 7. Reliability and Security Considerations

The most important failure mode is a configuration that appears to proxy
traffic while silently allowing direct egress. The harness network MUST
therefore be internal-only, and that property MUST be tested independently of
the harness's proxy or base URL configuration.

The second most important failure mode is a gateway that allows more provider
surface than intended. The gateway MUST deny by default and MUST require an
explicit method and path allowlist.

The third most important failure mode is a gateway that cannot log but
continues forwarding. The gateway MUST fail closed when it cannot write a
required audit event.

The fourth most important failure mode is coupling the gateway to provider
authentication schemes. That would require provider-specific credential logic
for every harness and provider. The gateway MUST instead treat authentication
as end-to-end provider request data while it enforces egress, allowlists, and
audit.

## 8. References

### 8.1. Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174, May 2017.

### 8.2. Informative References

- [RFC7322] Flanagan, H. and S. Ginoza, "RFC Style Guide", RFC 7322,
  September 2014.
- [RFC2026] Bradner, S., "The Internet Standards Process -- Revision 3",
  BCP 9, RFC 2026, October 1996.
