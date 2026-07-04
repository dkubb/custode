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
    PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 \
        PROPTEST_RNG_SEED=00000000000000000000000000000014 \
        {{cargo}} test-workspace

docs:
    mado check README.md docs/IDEA.md docs/ARCHITECTURE.md docs/STRESS.md

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
        --max-missed-regions 910 \
        --max-missed-functions 121 \
        --max-missed-lines 521 \
        --max-missed-branches 41 \
        --per-file-ratchet tests/coverage_summary/proptests-ratchet.tsv \
        target/coverage/proptests.json

mutants:
    {{cargo}} mutants-all

check: fmt-check lint shell-check test dockerfile-check

ci: check deny

stress-check:
    just ci
    scripts/test-verify-audit-log.sh
    just docker-test
    mkdir -p target/fuzz-corpus/{accepted_path_set_path,allowed_operation_parse,upstream_origin_parse}
    cargo fuzz run accepted_path_set_path target/fuzz-corpus/accepted_path_set_path -- -runs=256
    cargo fuzz run allowed_operation_parse target/fuzz-corpus/allowed_operation_parse -- -runs=256
    cargo fuzz run upstream_origin_parse target/fuzz-corpus/upstream_origin_parse -- -runs=256
