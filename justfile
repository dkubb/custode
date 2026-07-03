set shell := ["bash", "--noprofile", "--norc", "-o", "errexit", "-o", "errtrace", "-o", "nounset", "-o", "pipefail", "-c"]

cargo := "scripts/pinned-cargo.sh"

default:
    just --list

fmt:
    {{cargo}} fmt-all

fmt-check:
    {{cargo}} fmt-check-all

lint:
    {{cargo}} clippy-all

test:
    {{cargo}} test-workspace

docs:
    mado check README.md docs/IDEA.md docs/ARCHITECTURE.md

deny:
    {{cargo}} deny-check

shell-check:
    shfmt -d -i 2 -ci scripts/*.sh
    shellcheck -S style -x scripts/*.sh

dockerfile-check:
    docker buildx build --check .

docker-build:
    docker compose build proxy harness

docker-test:
    scripts/container-test.sh

coverage:
    mkdir -p target/coverage
    {{cargo}} coverage
    scripts/check-coverage-summary.sh target/coverage/unit.json

coverage-proptests:
    mkdir -p target/coverage
    PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 \
        PROPTEST_RNG_SEED=00000000000000000000000000000014 \
        {{cargo}} coverage-proptests
    scripts/check-coverage-summary.sh \
        --exclude-test-mods \
        --max-missed-regions 602 \
        --max-missed-functions 98 \
        --max-missed-lines 375 \
        --max-missed-branches 34 \
        target/coverage/proptests.json

mutants:
    {{cargo}} mutants-all

check: fmt-check lint shell-check test dockerfile-check

ci: check deny
