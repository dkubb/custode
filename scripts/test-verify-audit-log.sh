#!/usr/bin/env -S -u BASHOPTS -u BASH_ENV -u CDPATH -u GLOBIGNORE -u SHELLOPTS bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# shellcheck shell=bash
# Fixture tests for scripts/verify-audit-log.sh.

readonly TAP_TEST_COUNT=14
readonly DIGEST="0000000000000000000000000000000000000000000000000000000000000000"
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
  local decision="${3:-allowed}"
  local request_id

  request_id=$(printf 'req-%s-%016x' "${run_token}" "${sequence}")

  case "${decision}" in
    allowed)
      jq -nc --arg request_id "${request_id}" '{
        version: 3,
        timestamp: "1970-01-01T00:00:00.000000000Z",
        request_id: $request_id,
        decision: "allowed",
        method: "GET",
        path: "/v1/models",
        query: null,
        upstream_origin: "https://api.openai.com",
        upstream_path: "/v1/models",
        upstream_query: null,
        status: 200,
        request_body: {state: "empty"},
        response_body: {state: "empty"},
        error_class: null
      }'
      ;;
    denied)
      jq -nc --arg request_id "${request_id}" '{
        version: 3,
        timestamp: "1970-01-01T00:00:00.000000000Z",
        request_id: $request_id,
        decision: "denied",
        method: "DELETE",
        path: "/v1/models",
        query: null,
        upstream_origin: "https://api.openai.com",
        upstream_path: null,
        upstream_query: null,
        status: 403,
        request_body: {state: "not_observed"},
        response_body: {state: "not_observed"},
        error_class: "method_denied"
      }'
      ;;
    response_error)
      jq -nc --arg request_id "${request_id}" --arg digest "${DIGEST}" '{
        version: 3,
        timestamp: "1970-01-01T00:00:00.000000000Z",
        request_id: $request_id,
        decision: "response_error",
        method: "GET",
        path: "/v1/models",
        query: null,
        upstream_origin: "https://api.openai.com",
        upstream_path: "/v1/models",
        upstream_query: null,
        status: 200,
        request_body: {state: "empty"},
        response_body: {state: "non_empty", bytes: 1, blake3: $digest},
        error_class: "response_body_too_large"
      }'
      ;;
    upstream_error)
      jq -nc --arg request_id "${request_id}" '{
        version: 3,
        timestamp: "1970-01-01T00:00:00.000000000Z",
        request_id: $request_id,
        decision: "upstream_error",
        method: "GET",
        path: "/v1/models",
        query: null,
        upstream_origin: "https://api.openai.com",
        upstream_path: "/v1/models",
        upstream_query: null,
        status: 504,
        request_body: {state: "empty"},
        response_body: {state: "not_observed"},
        error_class: "upstream_timeout"
      }'
      ;;
    *)
      printf 'unknown fixture decision: %s\n' "${decision}" >&2
      return 1
      ;;
  esac
}

mutated_event() {
  local filter="${1}"

  shift
  event "$@" | jq -c --arg digest "${DIGEST}" "${filter}"
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
  "$(event "${RUN_A}" 2 "denied")" \
  "$(event "${RUN_B}" 1 "upstream_error")" \
  "$(event "${RUN_B}" 2 "response_error")"

missing_log=$(fixture_log "missing")

torn_log=$(fixture_log "torn")
printf '%s' "$(event "${RUN_A}" 1)" >"${torn_log}"

invalid_json_log=$(fixture_log "invalid-json")
write_log "${invalid_json_log}" "$(event "${RUN_A}" 1)" "{"

multi_object_line_log=$(fixture_log "multi-object-line")
printf '%s %s\n' "$(event "${RUN_A}" 1)" "$(event "${RUN_A}" 2)" >"${multi_object_line_log}"

duplicate_log=$(fixture_log "duplicate")
write_log "${duplicate_log}" "$(event "${RUN_A}" 1)" "$(event "${RUN_A}" 1)"

out_of_order_log=$(fixture_log "out-of-order")
write_log "${out_of_order_log}" "$(event "${RUN_A}" 2)" "$(event "${RUN_A}" 1)"

zero_sequence_log=$(fixture_log "zero-sequence")
write_log \
  "${zero_sequence_log}" \
  "$(mutated_event '.request_id = "req-000000000000000a-000000000000000b-0000000000000000"' "${RUN_A}" 1)"

missing_field_log=$(fixture_log "missing-field")
write_log "${missing_field_log}" "$(mutated_event 'del(.status)' "${RUN_A}" 1)"

unknown_field_log=$(fixture_log "unknown-field")
write_log \
  "${unknown_field_log}" \
  "$(mutated_event '.headers = {"authorization": "secret"}' "${RUN_A}" 1)"

invalid_decision_log=$(fixture_log "invalid-decision")
write_log \
  "${invalid_decision_log}" \
  "$(mutated_event '.decision = "configuration_error"' "${RUN_A}" 1)"

invalid_body_log=$(fixture_log "invalid-body")
write_log \
  "${invalid_body_log}" \
  "$(mutated_event ".request_body = {\"state\": \"non_empty\", \"bytes\": 0, \"blake3\": \$digest}" "${RUN_A}" 1)"

allowed_error_log=$(fixture_log "allowed-error")
write_log \
  "${allowed_error_log}" \
  "$(mutated_event '.error_class = "method_denied"' "${RUN_A}" 1)"

denied_upstream_log=$(fixture_log "denied-upstream")
write_log \
  "${denied_upstream_log}" \
  "$(mutated_event '.upstream_path = "/v1/models"' "${RUN_A}" 1 "denied")"

printf 'TAP version 13\n'
printf '1..%d\n' "${TAP_TEST_COUNT}"

run_ok "accepts valid audit logs" scripts/verify-audit-log.sh "${valid_log}"
run_fails "rejects missing audit logs" scripts/verify-audit-log.sh "${missing_log}"
run_fails "rejects non-newline-terminated audit logs" scripts/verify-audit-log.sh "${torn_log}"
run_fails "rejects invalid NDJSON" scripts/verify-audit-log.sh "${invalid_json_log}"
run_fails "rejects multiple events on one line" scripts/verify-audit-log.sh "${multi_object_line_log}"
run_fails "rejects duplicate request IDs" scripts/verify-audit-log.sh "${duplicate_log}"
run_ok "accepts out-of-order run sequences" scripts/verify-audit-log.sh "${out_of_order_log}"
run_fails "rejects zero request sequences" scripts/verify-audit-log.sh "${zero_sequence_log}"
run_fails "rejects missing audit fields" scripts/verify-audit-log.sh "${missing_field_log}"
run_fails "rejects unknown audit fields" scripts/verify-audit-log.sh "${unknown_field_log}"
run_fails "rejects unknown decisions" scripts/verify-audit-log.sh "${invalid_decision_log}"
run_fails "rejects invalid body summaries" scripts/verify-audit-log.sh "${invalid_body_log}"
run_fails "rejects allowed event error classes" scripts/verify-audit-log.sh "${allowed_error_log}"
run_fails "rejects denied upstream targets" scripts/verify-audit-log.sh "${denied_upstream_log}"

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi
