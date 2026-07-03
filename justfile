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
    PROPTEST_RNG_SEED=00000000000000000000000000000014 cargo coverage-proptests
    scripts/check-coverage-summary.sh \
        --exclude-test-mods \
        --max-missed-regions 595 \
        --max-missed-functions 89 \
        --max-missed-lines 371 \
        --max-missed-branches 26 \
        target/coverage/proptests.json

mutants:
    cargo mutants-all

check: fmt-check lint test dockerfile-check

ci: check deny
