set shell := ["bash", "--noprofile", "--norc", "-o", "errexit", "-o", "errtrace", "-o", "nounset", "-o", "pipefail", "-c"]

export PATH := env_var('HOME') + '/.cargo/bin:' + env_var('PATH')

default:
    just --list

fmt:
    cargo fmt-all

fmt-check:
    cargo fmt-check-all

lint:
    cargo clippy-all

test:
    cargo test-workspace

docs:
    mado check README.md docs/IDEA.md docs/ARCHITECTURE.md

deny:
    cargo deny-check

dockerfile-check:
    docker buildx build --check .

docker-build:
    docker compose build proxy harness

docker-test:
    scripts/container-test.sh

coverage:
    cargo coverage
    scripts/check-coverage-summary.sh target/coverage/unit.json

coverage-proptests:
    cargo coverage-proptests
    scripts/check-coverage-summary.sh \
        --max-missed-regions 621 \
        --max-missed-functions 68 \
        --max-missed-lines 472 \
        --max-missed-branches 36 \
        target/coverage/proptests.json

mutants:
    cargo mutants-all

check: fmt-check lint test dockerfile-check

ci: check deny
