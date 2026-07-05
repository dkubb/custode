# Custode

Custode runs an untrusted coding harness behind a small Rust provider proxy.

The harness container has only the internal Docker network. It can read and
write `./workspace` and can reach only `http://proxy:8080`. The proxy
container has an egress network, a method/path allowlist, and an NDJSON audit
log.

## Security Model

Custode is meant to make hidden outbound traffic easier to block and inspect.
It trusts the operator, not the harness's external communications. It assumes
Docker, the host kernel, the provider, and the configured upstream TLS endpoint
are trusted. It does not claim to survive a Docker/container escape.

The harness owns its provider credentials and configuration through
`secrets/env`. Custode does not interpret provider authentication schemes.
Instead, it denies direct egress and forwards only inspectable HTTP requests
that pass the configured method/path allowlist.

## Requirements

- Docker with Compose v2.
- Harness-local settings and credentials in `secrets/env`.
- Rust and Cargo for local development gates.
- `cargo-deny`, `cargo-mutants`, and `mado` for the optional full gate set.

## Create Harness Env

Create the harness environment file and workspace directory:

```sh
mkdir -p secrets workspace
cp secrets/env.example secrets/env
chmod 600 secrets/env
```

`secrets/env` is ignored by Git. It is loaded into the harness process
environment and mounted read-only at `/etc/environment` inside the harness
container. Values in that file are visible to the untrusted harness by design.
Put only credentials and config that the harness is intended to use there.

## Build

Build both images:

```sh
export CUSTODE_HARNESS_ENV_FILE=./secrets/env
docker compose build proxy harness
```

The proxy image is a `scratch` runtime image containing only the statically
linked Rust proxy. The harness image is intentionally generic; choose the
harness package and command with environment variables.

## Claude Code Harness

Claude Code can be installed into the harness image through npm. Anthropic's
official docs also describe native, Homebrew, package-manager, and npm
install paths; this Dockerfile uses the npm path because the harness image
already supports npm package injection.

First build and smoke-test the CLI:

```sh
export CUSTODE_HARNESS_ENV_FILE=./secrets/env
export CUSTODE_HARNESS_NPM_PACKAGES='@anthropic-ai/claude-code'
docker compose build harness

export CUSTODE_HARNESS_COMMAND='claude --version'
docker compose run --rm harness
```

Then run Claude through the proxy:

Add or uncomment the Claude API key in `secrets/env`:

```text
ANTHROPIC_API_KEY=sk-ant-api03-...
```

```sh
anthropic_ops='POST:prefix:/v1/messages'
anthropic_ops="${anthropic_ops},GET:prefix:/v1/models"

export CUSTODE_HARNESS_ENV_FILE=./secrets/env
export CUSTODE_UPSTREAM_ORIGIN=https://api.anthropic.com
export CUSTODE_ALLOWED_OPERATIONS="${anthropic_ops}"
export CUSTODE_HARNESS_NPM_PACKAGES='@anthropic-ai/claude-code'

claude_cmd="claude --bare -p 'what is 2+2?'"
claude_cmd="${claude_cmd} --output-format text --max-budget-usd 0.01"
export CUSTODE_HARNESS_COMMAND="${claude_cmd}"

docker compose up --abort-on-container-exit --exit-code-from harness
```

The proxy forwards provider authorization headers from the harness request. It
does not know whether the provider uses bearer tokens, `x-api-key`, cookies,
or another scheme.

## Codex Harness

Codex can also be installed into the harness image through npm. OpenAI's
official docs describe standalone, npm, and Homebrew installs; this Dockerfile
uses the npm path for the same reason as Claude Code.

Build and smoke-test the CLI:

```sh
export CUSTODE_HARNESS_ENV_FILE=./secrets/env
export CUSTODE_HARNESS_NPM_PACKAGES='@openai/codex'
docker compose build harness

export CUSTODE_HARNESS_COMMAND='codex --version'
docker compose run --rm harness
```

For model calls, route Codex to the proxy. The compose file exports
`OPENAI_BASE_URL=http://proxy:8080` for clients that honor it. Current Codex
CLI docs also support one-off config overrides with `-c`, and the OpenAI
provider base URL key is `openai_base_url`.

A non-interactive command should use the proxy URL as the OpenAI API base URL:

Add or uncomment the OpenAI API key in `secrets/env`:

```text
OPENAI_API_KEY=sk-...
```

```sh
openai_ops='GET:exact:/v1/models,POST:prefix:/v1/responses'
openai_ops="${openai_ops},POST:prefix:/v1/chat/completions"

export CUSTODE_HARNESS_ENV_FILE=./secrets/env
export CUSTODE_UPSTREAM_ORIGIN=https://api.openai.com
export CUSTODE_ALLOWED_OPERATIONS="${openai_ops}"
export CUSTODE_HARNESS_NPM_PACKAGES='@openai/codex'

codex_cmd='codex exec'
codex_cmd="${codex_cmd} --dangerously-bypass-approvals-and-sandbox"
codex_cmd="${codex_cmd} --skip-git-repo-check --ephemeral"
codex_cmd="${codex_cmd} -c 'openai_base_url=\"http://proxy:8080/v1\"'"
codex_cmd="${codex_cmd} --cd /workspace 'what is 2+2?'"
export CUSTODE_HARNESS_COMMAND="${codex_cmd}"

docker compose up --abort-on-container-exit --exit-code-from harness
```

The `--dangerously-bypass-approvals-and-sandbox` flag belongs only inside this
externally sandboxed harness container.

## Audit Log

The proxy writes one NDJSON audit event per handled request:

```sh
docker run --rm \
  -v custode_proxy-logs:/logs \
  custode-harness:local \
  bash -c 'tail -n 20 /logs/proxy.ndjson'
```

Remove stopped containers while preserving audit logs:

```sh
docker compose down --remove-orphans
```

Remove containers and the audit-log volume:

```sh
docker compose down --volumes
```

## Local Gates

The main development gates are:

```sh
just check        # fmt-check, lint, shell, toolchain, test, Dockerfile check
just ci           # check plus cargo-deny
just docs         # Markdown lint
just docker-build # image build
just docker-test  # container tests: static linkage, health, egress, audit log
just coverage     # cargo llvm-cov summary
just stress-check # ci, verifier fixtures, docker-test, fuzz smoke tests
just mutants      # cargo-mutants mutation testing
```

The test suite includes inline unit tests, inline property tests, and
integration tests in `tests/gateway.rs` that run the compiled binary against
a local recording upstream.

## Design Documents

- [IDEA.md](docs/IDEA.md)
- [ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Upstream Harness Docs

- [Claude Code setup](https://code.claude.com/docs/en/setup)
- [Codex CLI](https://developers.openai.com/codex/cli)
- [Codex configuration reference](https://developers.openai.com/codex/config-reference)
