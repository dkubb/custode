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
  local line
  local line_number=0

  while IFS= read -r line; do
    line_number=$((line_number + 1))
    if ! jq -e -s 'length == 1 and (.[0] | type) == "object"' <<<"${line}" >/dev/null; then
      fail "audit log line ${line_number} is not one JSON object: ${audit_log}"
    fi
  done <"${audit_log}"
}

require_valid_audit_events() {
  local audit_log="${1}"

  if ! jq -e -s '
    def expected_keys:
      [
        "decision",
        "error_class",
        "method",
        "path",
        "query",
        "request_body",
        "request_id",
        "response_body",
        "status",
        "timestamp",
        "upstream_origin",
        "upstream_path",
        "upstream_query",
        "version"
      ];

    def exact_event_keys:
      (keys | sort) == expected_keys;

    def positive_integer:
      type == "number" and . == floor and . > 0;

    def valid_status:
      type == "number" and . == floor and . >= 100 and . <= 999;

    def valid_timestamp:
      type == "string"
      and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9}Z$");

    def valid_blake3:
      type == "string" and test("^[0-9a-f]{64}$");

    def valid_body_summary:
      type == "object"
      and if .state == "not_observed" or .state == "empty" then
        (keys | sort) == ["state"]
      elif .state == "non_empty" then
        (keys | sort) == ["blake3", "bytes", "state"]
        and (.bytes | positive_integer)
        and (.blake3 | valid_blake3)
      else
        false
      end;

    def observed_body:
      .state == "empty" or .state == "non_empty";

    def denied_error_classes:
      [
        "absolute_form_unsupported",
        "connect_unsupported",
        "dot_segment",
        "encoded_path_separator",
        "invalid_percent_encoding",
        "invalid_request_connection_header",
        "method_denied",
        "non_origin_form",
        "path_denied",
        "path_too_long",
        "query_too_long",
        "request_body_read_failed",
        "request_body_timeout",
        "request_body_too_large",
        "request_headers_too_large",
        "too_many_requests"
      ];

    def response_error_classes:
      [
        "downstream_closed",
        "invalid_response_connection_header",
        "response_body_too_large",
        "response_headers_too_large",
        "response_stream_timeout",
        "upstream_response_stream_failed",
        "upstream_response_timeout"
      ];

    def upstream_error_classes:
      [
        "upstream_connect_failed",
        "upstream_request_failed",
        "upstream_timeout"
      ];

    def contains_value($values; $value):
      $values | index($value) != null;

    def valid_decision:
      contains_value(
        ["allowed", "denied", "upstream_error", "response_error"];
        .
      );

    def valid_error_class:
      if .decision == "allowed" then
        .error_class == null
      elif .decision == "denied" then
        (.error_class | type) == "string"
        and contains_value(denied_error_classes; .error_class)
      elif .decision == "response_error" then
        (.error_class | type) == "string"
        and contains_value(response_error_classes; .error_class)
      elif .decision == "upstream_error" then
        (.error_class | type) == "string"
        and contains_value(upstream_error_classes; .error_class)
      else
        false
      end;

    def valid_target_state:
      if .decision == "denied" then
        .upstream_path == null and .upstream_query == null
      elif .decision == "allowed"
        or .decision == "response_error"
        or .decision == "upstream_error" then
        (.upstream_path | type) == "string"
        and (.upstream_query == null or (.upstream_query | type) == "string")
      else
        false
      end;

    def valid_body_state:
      if .decision == "allowed" then
        (.request_body | observed_body) and (.response_body | observed_body)
      elif .decision == "denied" then
        .response_body.state == "not_observed"
      elif .decision == "upstream_error" then
        (.request_body | observed_body) and .response_body.state == "not_observed"
      elif .decision == "response_error" then
        (.request_body | observed_body)
        and if .error_class == "invalid_response_connection_header"
          or .error_class == "response_headers_too_large" then
          .response_body.state == "not_observed"
        elif .error_class == "response_body_too_large" then
          .response_body.state == "non_empty"
        else
          (.response_body | observed_body)
        end
      else
        false
      end;

    def audit_id:
      . as $event
      | if ($event | type) != "object" then
          error("audit event is not an object")
        elif ($event | exact_event_keys | not) then
          error("audit event does not match schema fields")
        elif $event.version != 3 then
          error("audit event has invalid schema version")
        elif ($event.timestamp | valid_timestamp | not) then
          error("audit event has invalid timestamp")
        elif ($event.decision | type) != "string" or ($event.decision | valid_decision | not) then
          error("audit event has invalid decision")
        elif ($event.method | type) != "string" then
          error("audit event has invalid method")
        elif ($event.path | type) != "string" then
          error("audit event has invalid path")
        elif ($event.query != null and ($event.query | type) != "string") then
          error("audit event has invalid query")
        elif ($event.upstream_origin | type) != "string" then
          error("audit event has invalid upstream_origin")
        elif ($event.status | valid_status | not) then
          error("audit event has invalid status")
        elif ($event.request_body | valid_body_summary | not) then
          error("audit event has invalid request_body")
        elif ($event.response_body | valid_body_summary | not) then
          error("audit event has invalid response_body")
        elif ($event | valid_error_class | not) then
          error("audit event has invalid error_class")
        elif ($event | valid_target_state | not) then
          error("audit event has invalid upstream target")
        elif ($event | valid_body_state | not) then
          error("audit event has invalid body state")
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
          $request_id
        end;

    [ .[] | audit_id ] as $ids
    | if (($ids | unique | length) != ($ids | length)) then
        error("audit log has duplicate request_id")
      else
        true
      end
    | true
  ' <"${audit_log}" >/dev/null; then
    fail "audit log has invalid audit events: ${audit_log}"
  fi
}

require_single_path "$@"

audit_log="${1}"
require_readable_file "${audit_log}"
require_newline_terminated "${audit_log}"
require_valid_ndjson "${audit_log}"
require_valid_audit_events "${audit_log}"
