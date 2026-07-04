# Custode Repo-Local Stress Hardening

Status of This Memo

This document records the maintained repo-local stress-hardening gates for
Custode. It is not a claim that Custode survives host compromise, Docker
daemon compromise, kernel compromise, or a container escape. It describes the
checks that are expected to run without privileged host tooling.

## 1. Success Criteria

The repo-local stress gate succeeds when all of the following are true:

- ordinary CI is green;
- audit-log verifier fixture tests pass;
- container topology tests prove the harness cannot use direct egress paths
  covered by the test harness;
- the proxy audit log emitted during container tests is valid NDJSON under
  `scripts/verify-audit-log.sh`;
- bounded fuzz smoke tests run for the parser oracles that are exposed only
  under `cfg(fuzzing)`.

The maintained entrypoint is:

```sh
just stress-check
```

The recipe intentionally uses only repo-local, non-privileged checks. It does
not run packet capture, kernel fault injection, device-mapper tests, traffic
shaping, or host firewall manipulation.

## 2. Stress Gate Contents

`just stress-check` runs these checks in order:

- `just ci`, which covers formatting, linting, shell checks, Rust tests,
  Dockerfile checks, and `cargo deny`;
- `scripts/test-verify-audit-log.sh`, which exercises the audit verifier
  fixture contract;
- `just docker-test`, which builds the containers, checks the static proxy
  binary, starts the Compose topology, checks internal-only harness networks,
  denies direct harness egress, confirms gateway reachability, and validates
  the proxy audit log;
- `cargo fuzz run accepted_path_set_path ... -- -runs=256`;
- `cargo fuzz run allowed_operation_parse ... -- -runs=256`;
- `cargo fuzz run upstream_origin_parse ... -- -runs=256`.

The fuzz smoke tests use corpus directories under `target/fuzz-corpus/` so
normal smoke runs do not add files under `fuzz/corpus/`.

## 3. Audit Log Verification

`scripts/verify-audit-log.sh` accepts exactly one audit log path and fails
closed when:

- the file is missing or unreadable;
- a non-empty file is not newline terminated;
- any line is invalid NDJSON or not a JSON object;
- any event has a missing, malformed, or duplicate `request_id`;
- any request sequence is zero.

The verifier does not require request IDs to appear in sequence order. The
gateway can write response audit events in completion order while requests run
concurrently.

The fixture suite is:

```sh
scripts/test-verify-audit-log.sh
```

The container stress path also copies `/var/log/custode/proxy.ndjson` out of
the proxy container and runs the verifier against the real emitted log.

## 4. Container Egress Probes

`scripts/container-test.sh` is the maintained repo-local container probe. It
currently asserts that:

- the proxy and harness images build;
- `/custode-proxy` is statically linked in the proxy image;
- the proxy container becomes healthy;
- the proxy publishes no host ports;
- harness networks are marked internal-only;
- the harness cannot fetch an external URL directly;
- the harness cannot reach a raw public IP over HTTP directly;
- the harness cannot open TCP to public DNS directly;
- the harness can reach the gateway on the internal network;
- the proxy audit log is valid.

These probes are intentionally black-box Compose checks. They do not replace
host firewall review, Docker daemon hardening, or packet capture.

## 5. Parser and Gateway Boundary Coverage

The stress suite relies on normal Rust tests for request-target boundary
behavior. Those tests cover:

- authority-looking origin paths such as `//evil.example/...`;
- mixed-case encoded dot segments;
- mixed-case encoded separators;
- maximum path and query requests that should pass unchanged;
- max-plus-one path and query requests that should be denied and audited with
  bounded truncation metadata.

Handler-reachable denials must record one audit event and no upstream request.
Malformed requests that are rejected before the handler are expected to record
no upstream request and no audit event.

## 6. Fuzz Oracles

Fuzz-only parser entrypoints live behind `cfg(fuzzing)`. They do not make
parser internals public in normal builds.

Scoped `cargo-mutants` runs with unit tests do not treat these facades as
load-bearing evidence. Exclude fuzz-only facade replacements from that gate
and use the matching `cargo fuzz run` target as the maintained proof.

The current fuzz targets are:

- `accepted_path_set_path`, which checks that accepted origin-form paths are
  preserved by `Url::set_path`;
- `allowed_operation_parse`, which checks totality of allowed-operation
  parsing over arbitrary input bytes;
- `upstream_origin_parse`, which checks totality of upstream-origin parsing
  over arbitrary input bytes.

Run one target manually with:

```sh
cargo fuzz run accepted_path_set_path \
  target/fuzz-corpus/accepted_path_set_path \
  -- -runs=256
```

Long-running fuzz campaigns may use persistent corpuses under `fuzz/corpus/`.
Those campaigns are outside the default repo-local stress gate.

## 7. Manual And Future Work

The following tools remain manual or future work because they are privileged,
host-specific, slow, or noisy enough that they do not belong in the default
repo-local gate:

- packet capture with `tcpdump` or equivalent tools;
- HTTP slow-client tools such as `slowhttptest`;
- Linux traffic shaping or network fault injection;
- device-mapper or filesystem-fault injection;
- host firewall rule audits;
- long-running fuzz campaigns.

When one of these tools is used, record the command, host assumptions, and
observed result in the relevant issue or review notes. Do not add the tool to
`just stress-check` unless it can run without special host privileges and
without making the gate flaky.
