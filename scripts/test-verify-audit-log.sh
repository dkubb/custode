#!/usr/bin/env -S bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# Fixture tests for scripts/verify-audit-log.sh.

readonly TAP_TEST_COUNT=7
readonly RUN_A="000000000000000a-000000000000000b"
readonly RUN_B="000000000000000c-000000000000000d"

test_number=0
failed=0
temporary_dir=""

cleanup() {
  if [[ -n "${temporary_dir}" ]]; then
    rm -rf "${temporary_dir}"
  fi
}
trap cleanup EXIT

tap_diag() {
  local line

  if [[ -z "${1}" ]]; then
    return 0
  fi

  while IFS= read -r line; do
    printf '# %s\n' "${line}"
  done <<<"${1}"
}

ok() {
  local name="${1}"

  printf 'ok %d - %s\n' "${test_number}" "${name}"
}

not_ok() {
  local name="${1}"
  local output="${2}"

  printf 'not ok %d - %s\n' "${test_number}" "${name}"
  tap_diag "${output}"
  failed=1
}

run_ok() {
  local name="${1}"
  local output

  shift
  test_number=$((test_number + 1))
  if output="$("$@" 2>&1)"; then
    ok "${name}"
    return 0
  fi

  not_ok "${name}" "${output}"
}

run_fails() {
  local name="${1}"
  local output

  shift
  test_number=$((test_number + 1))
  if output="$("$@" 2>&1)"; then
    not_ok "${name}" "command unexpectedly succeeded"
    return 0
  fi

  ok "${name}"
}

event() {
  local run_token="${1}"
  local sequence="${2}"

  printf '{"request_id":"req-%s-%016x"}' "${run_token}" "${sequence}"
}

fixture_log() {
  local name="${1}"

  printf '%s/%s.ndjson' "${temporary_dir}" "${name}"
}

write_log() {
  local path="${1}"

  shift
  : >"${path}"
  for line in "$@"; do
    printf '%s\n' "${line}" >>"${path}"
  done
}

temporary_dir=$(mktemp -d)

valid_log=$(fixture_log "valid")
write_log \
  "${valid_log}" \
  "$(event "${RUN_A}" 1)" \
  "$(event "${RUN_A}" 2)" \
  "$(event "${RUN_B}" 1)"

missing_log=$(fixture_log "missing")

torn_log=$(fixture_log "torn")
printf '%s' "$(event "${RUN_A}" 1)" >"${torn_log}"

invalid_json_log=$(fixture_log "invalid-json")
write_log "${invalid_json_log}" "$(event "${RUN_A}" 1)" "{"

duplicate_log=$(fixture_log "duplicate")
write_log "${duplicate_log}" "$(event "${RUN_A}" 1)" "$(event "${RUN_A}" 1)"

out_of_order_log=$(fixture_log "out-of-order")
write_log "${out_of_order_log}" "$(event "${RUN_A}" 2)" "$(event "${RUN_A}" 1)"

zero_sequence_log=$(fixture_log "zero-sequence")
write_log "${zero_sequence_log}" '{"request_id":"req-000000000000000a-000000000000000b-0000000000000000"}'

printf 'TAP version 13\n'
printf '1..%d\n' "${TAP_TEST_COUNT}"

run_ok "accepts valid audit logs" scripts/verify-audit-log.sh "${valid_log}"
run_fails "rejects missing audit logs" scripts/verify-audit-log.sh "${missing_log}"
run_fails "rejects non-newline-terminated audit logs" scripts/verify-audit-log.sh "${torn_log}"
run_fails "rejects invalid NDJSON" scripts/verify-audit-log.sh "${invalid_json_log}"
run_fails "rejects duplicate request IDs" scripts/verify-audit-log.sh "${duplicate_log}"
run_ok "accepts out-of-order run sequences" scripts/verify-audit-log.sh "${out_of_order_log}"
run_fails "rejects zero request sequences" scripts/verify-audit-log.sh "${zero_sequence_log}"

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi
