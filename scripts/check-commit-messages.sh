#!/usr/bin/env -S -u BASHOPTS -u BASH_ENV -u CDPATH -u GLOBIGNORE -u SHELLOPTS bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# shellcheck shell=bash
# Checks conventional subjects and 72-column wrapping for a commit range.

readonly RANGE=${1:-origin/main..HEAD}
readonly SUBJECT_PATTERN='^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\([a-z0-9][a-z0-9._/-]*\))?!?: [a-z0-9]'

failed=false
while IFS= read -r commit; do
  subject=$(git show -s --format=%s "${commit}")
  if [[ ! ${subject} =~ ${SUBJECT_PATTERN} ]]; then
    printf 'commit-message: %s has a non-conventional subject: %s\n' \
      "${commit}" "${subject}" >&2
    failed=true
  fi

  while IFS= read -r line; do
    if ((${#line} > 72)); then
      printf 'commit-message: %s has a %d-column line: %s\n' \
        "${commit}" "${#line}" "${line}" >&2
      failed=true
    fi
  done < <(git show -s --format=%B "${commit}")
done < <(git rev-list --reverse "${RANGE}")

if [[ ${failed} == true ]]; then
  exit 1
fi

printf 'commit messages satisfy the repository policy\n'
