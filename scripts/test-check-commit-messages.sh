#!/usr/bin/env -S -u BASHOPTS -u BASH_ENV -u CDPATH -u GLOBIGNORE -u SHELLOPTS bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# shellcheck shell=bash
# Exercises accepted and rejected commit-message fixtures.

CHECKER=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-commit-messages.sh
readonly CHECKER
fixture=$(mktemp -d "${TMPDIR:-/tmp}/custode-commit-messages.XXXXXX")
trap 'rm -rf "${fixture}"' EXIT

git -C "${fixture}" init --quiet
git -C "${fixture}" config user.name 'Commit Fixture'
git -C "${fixture}" config user.email 'fixture@example.com'
git -C "${fixture}" commit --quiet --allow-empty -m 'test(repo): establish fixture base'
base=$(git -C "${fixture}" rev-parse HEAD)

git -C "${fixture}" commit --quiet --allow-empty \
  -m 'fix(shell): accept wrapped conventional message' \
  -m 'Explain why the fixture exists without exceeding the line limit.'
(
  cd "${fixture}"
  "${CHECKER}" "${base}..HEAD"
)

git -C "${fixture}" commit --quiet --allow-empty \
  -m 'Reject non-conventional subject'
if (
  cd "${fixture}"
  "${CHECKER}" 'HEAD^..HEAD' >/dev/null 2>&1
); then
  printf 'commit-message fixture: non-conventional subject was accepted\n' >&2
  exit 1
fi

git -C "${fixture}" commit --quiet --allow-empty \
  -m 'fix(repo): reject an overlong body' \
  -m 'This fixture body is intentionally longer than seventy-two columns so the checker must reject it.'
if (
  cd "${fixture}"
  "${CHECKER}" 'HEAD^..HEAD' >/dev/null 2>&1
); then
  printf 'commit-message fixture: overlong body was accepted\n' >&2
  exit 1
fi

printf 'commit-message fixtures passed\n'
