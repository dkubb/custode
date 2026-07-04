#!/usr/bin/env -S bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# Verifies a Custode audit log as newline-delimited JSON.

usage() {
  printf 'usage: %s AUDIT_LOG\n' "${0##*/}" >&2
}

fail() {
  printf 'verify-audit-log: %s\n' "${1}" >&2
  exit 1
}

require_single_path() {
  if [[ "$#" -ne 1 ]]; then
    usage
    exit 64
  fi
}

require_readable_file() {
  local audit_log="${1}"

  if [[ ! -f "${audit_log}" ]]; then
    fail "audit log does not exist: ${audit_log}"
  fi

  if [[ ! -r "${audit_log}" ]]; then
    fail "audit log is not readable: ${audit_log}"
  fi
}

require_newline_terminated() {
  local audit_log="${1}"
  local final_byte

  if [[ ! -s "${audit_log}" ]]; then
    return 0
  fi

  final_byte=$(tail -c 1 "${audit_log}" | od -An -tx1 | tr -d '[:space:]')
  if [[ "${final_byte}" != "0a" ]]; then
    fail "audit log is not newline-terminated: ${audit_log}"
  fi
}

require_valid_ndjson() {
  local audit_log="${1}"

  if ! jq -c . <"${audit_log}" >/dev/null; then
    fail "audit log contains invalid NDJSON: ${audit_log}"
  fi
}

require_valid_request_ids() {
  local audit_log="${1}"

  if ! jq -e -s '
    def audit_id:
      . as $event
      | if ($event | type) != "object" then
          error("audit event is not an object")
        else
          .request_id
        end as $request_id
      | if ($request_id | type) != "string" then
          error("audit event is missing string request_id")
        elif ($request_id | test("^req-[0-9a-f]{16}-[0-9a-f]{16}-[0-9a-f]{16}$") | not) then
          error("audit event has invalid request_id")
        elif $request_id[38:54] == "0000000000000000" then
          error("audit event has zero request sequence")
        else
          {
            request_id: $request_id,
            run_token: $request_id[4:37],
            sequence: $request_id[38:54]
          }
        end;

    [ .[] | audit_id ] as $ids
    | if (($ids | map(.request_id) | unique | length) != ($ids | length)) then
        error("audit log has duplicate request_id")
      else
        reduce $ids[] as $id ({};
          (.[$id.run_token] // "") as $last
          | if $last != "" and $id.sequence <= $last then
              error("audit log has non-monotonic request sequence")
            else
              .[$id.run_token] = $id.sequence
            end
        )
      end
    | true
  ' <"${audit_log}" >/dev/null; then
    fail "audit log has invalid request identifiers: ${audit_log}"
  fi
}

require_single_path "$@"

audit_log="${1}"
require_readable_file "${audit_log}"
require_newline_terminated "${audit_log}"
require_valid_ndjson "${audit_log}"
require_valid_request_ids "${audit_log}"
