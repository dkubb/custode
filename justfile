set shell := ["bash", "--noprofile", "--norc", "-o", "errexit", "-o", "errtrace", "-o", "nounset", "-o", "pipefail", "-c"]

export PATH := env_var('HOME') + '/.cargo/bin:' + env_var('PATH')

default:
    just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets --all-features --quiet

test:
    cargo test --workspace --all-features

docs:
    mado check README.md docs/IDEA.md docs/ARCHITECTURE.md

deny:
    cargo deny check --config .cargo/deny.toml

dockerfile-check:
    docker buildx build --check .

docker-build:
    docker compose build proxy harness

docker-test:
    scripts/container-test.sh

check: fmt-check lint test dockerfile-check

ci: check deny
