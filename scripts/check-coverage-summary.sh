#!/usr/bin/env -S bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# Checks a cargo-llvm-cov JSON summary against missed-state limits.

main() {
  local max_regions=0
  local max_functions=0
  local max_lines=0
  local max_branches=0
  local summary_path=""
  local exclude_test_mods=0

  while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
      --exclude-test-mods)
        exclude_test_mods=1
        shift
        ;;
      --max-missed-regions)
        require_count_option "${1}" "${2-}"
        max_regions="${2}"
        shift 2
        ;;
      --max-missed-functions)
        require_count_option "${1}" "${2-}"
        max_functions="${2}"
        shift 2
        ;;
      --max-missed-lines)
        require_count_option "${1}" "${2-}"
        max_lines="${2}"
        shift 2
        ;;
      --max-missed-branches)
        require_count_option "${1}" "${2-}"
        max_branches="${2}"
        shift 2
        ;;
      --help | -h)
        usage
        return 0
        ;;
      --*)
        printf 'unknown option: %s\n' "${1}" >&2
        usage >&2
        return 2
        ;;
      *)
        if [[ -n "${summary_path}" ]]; then
          printf 'unexpected argument: %s\n' "${1}" >&2
          usage >&2
          return 2
        fi
        summary_path="${1}"
        shift
        ;;
    esac
  done

  if [[ -z "${summary_path}" ]]; then
    usage >&2
    return 2
  fi

  if [[ ! -f "${summary_path}" ]]; then
    printf 'coverage summary not found: %s\n' "${summary_path}" >&2
    return 2
  fi

  local report_path
  report_path=$(mktemp "${TMPDIR:-/tmp}/custode-coverage-report.XXXXXX")
  if [[ "${exclude_test_mods}" -eq 0 ]]; then
    summary_report "${summary_path}" \
      "${max_regions}" \
      "${max_functions}" \
      "${max_lines}" \
      "${max_branches}" >"${report_path}"
  else
    detailed_report_excluding_test_modules "${summary_path}" \
      "${max_regions}" \
      "${max_functions}" \
      "${max_lines}" \
      "${max_branches}" >"${report_path}"
  fi

  local failed=0
  local metric
  local missed
  local maximum
  while IFS=$'\t' read -r metric missed maximum; do
    if ((missed > maximum)); then
      printf 'coverage metric %s has %s missed states; max is %s\n' \
        "${metric}" "${missed}" "${maximum}" >&2
      failed=1
    fi
  done <"${report_path}"

  rm -f "${report_path}"

  if [[ "${failed}" -ne 0 ]]; then
    return 1
  fi

  printf 'coverage summary is within missed-state limits\n'
}

summary_report() {
  local summary_path="${1}"
  local max_regions="${2}"
  local max_functions="${3}"
  local max_lines="${4}"
  local max_branches="${5}"

  jq --raw-output '
    def require_number($metric; $field):
      .data[0].totals[$metric][$field] as $value |
      if ($value | type) == "number" then
        $value
      else
        error("coverage summary missing numeric field: " + $metric + "." + $field)
      end;

    def require_pair($metric):
      (require_number($metric; "count")) as $count |
      (require_number($metric; "covered")) as $covered |
      if $covered <= $count then
        [$count, $covered]
      else
        error("coverage summary has impossible covered count: " + $metric + ".covered > " + $metric + ".count")
      end;

    [
      [
        "regions",
        (require_pair("regions") | .[0] - .[1]),
        $max_regions
      ],
      [
        "functions",
        (require_pair("functions") | .[0] - .[1]),
        $max_functions
      ],
      [
        "lines",
        (require_pair("lines") | .[0] - .[1]),
        $max_lines
      ],
      [
        "branches",
        (require_pair("branches") | .[0] - .[1]),
        $max_branches
      ]
    ] |
    .[] |
    @tsv
  ' \
    --argjson max_regions "${max_regions}" \
    --argjson max_functions "${max_functions}" \
    --argjson max_lines "${max_lines}" \
    --argjson max_branches "${max_branches}" \
    "${summary_path}"
}

validate_summary_totals() {
  local summary_path="${1}"

  jq --exit-status '
    def require_number($metric; $field):
      .data[0].totals[$metric][$field] as $value |
      if ($value | type) == "number" then
        $value
      else
        error("coverage summary missing numeric field: " + $metric + "." + $field)
      end;

    def require_pair($metric):
      (require_number($metric; "count")) as $count |
      (require_number($metric; "covered")) as $covered |
      if $covered <= $count then
        true
      else
        error("coverage summary has impossible covered count: " + $metric + ".covered > " + $metric + ".count")
      end;

    [
      require_pair("regions"),
      require_pair("functions"),
      require_pair("lines"),
      require_pair("branches")
    ] |
    all
  ' "${summary_path}" >/dev/null
}

detailed_report_excluding_test_modules() {
  local summary_path="${1}"
  local max_regions="${2}"
  local max_functions="${3}"
  local max_lines="${4}"
  local max_branches="${5}"
  local exclusions_path
  local events_path

  validate_summary_totals "${summary_path}"

  if ! jq --exit-status '
    .data[0].functions != null
      and (.data[0].files | all(.segments != null and .branches != null))
  ' "${summary_path}" >/dev/null; then
    printf 'detailed coverage JSON is required with --exclude-test-mods\n' >&2
    return 2
  fi
  validate_detailed_events_present "${summary_path}"

  exclusions_path=$(mktemp "${TMPDIR:-/tmp}/custode-coverage-exclusions.XXXXXX")
  events_path=$(mktemp "${TMPDIR:-/tmp}/custode-coverage-events.XXXXXX")
  build_exclusion_table "${summary_path}" >"${exclusions_path}"

  jq --raw-output '
    def as_bool:
      if type == "boolean" then . else . != 0 end;

    .data[0] as $data |
    [
      (
        $data.files[] as $file |
        ($file.filename) as $filename |
        ($file.segments // [])[] |
        . as $segment |
        ($segment[0] // 0) as $line |
        ($segment[2] // 0) as $count |
        (($segment[3] // false) | as_bool) as $has_count |
        select($line > 0 and $has_count and $count == 0) |
        ["line", $filename, $line]
      ),
      (
        $data.files[] as $file |
        ($file.filename) as $filename |
        ($file.segments // [])[] |
        . as $segment |
        ($segment[0] // 0) as $line |
        ($segment[2] // 0) as $count |
        (($segment[3] // false) | as_bool) as $has_count |
        (($segment[4] // false) | as_bool) as $is_region_entry |
        select($line > 0 and $has_count and $count == 0 and $is_region_entry) |
        ["region", $filename, $line]
      ),
      (
        $data.files[] as $file |
        ($file.filename) as $filename |
        ($file.branches // [])[] |
        . as $branch |
        ($branch[0] // 0) as $line |
        ($branch[1] // 0) as $start_column |
        ($branch[2] // 0) as $end_line |
        ($branch[3] // 0) as $end_column |
        [
          [0, ($branch[4] // 0)],
          [1, ($branch[5] // 0)]
        ][] as $arm |
        ($arm[0]) as $arm_index |
        ($arm[1]) as $count |
        select($line > 0 and $count == 0) |
        [
          "branch",
          $filename,
          $line,
          $start_column,
          $end_line,
          $end_column,
          $arm_index
        ]
      ),
      (
        ($data.functions // [])[] |
        select((.count // 0) == 0) |
        (.filenames[0] // "") as $filename |
        ((.regions[0][0]) // 0) as $line |
        select($filename != "" and $line > 0) |
        ["function", $filename, $line]
      )
    ][] |
    @tsv
  ' "${summary_path}" >"${events_path}"

  awk -F '\t' -v exclusions_path="${exclusions_path}" '
      FILENAME == exclusions_path {
        span_count[$1] += 1
        key = $1 SUBSEP span_count[$1]
        excluded_start[key] = $2
        excluded_end[key] = $3
        next
      }
      {
        metric = $1
        filename = $2
        line = $3
        excluded = 0
        for (span_index = 1; span_index <= span_count[filename]; span_index += 1) {
          key = filename SUBSEP span_index
          if (line >= excluded_start[key] && line <= excluded_end[key]) {
            excluded = 1
          }
        }
        if (excluded == 1) {
          next
        }
        if (metric == "line") {
          missed_lines[filename ":" line] = 1
        } else if (metric == "branch") {
          missed_branches[filename ":" line ":" $4 ":" $5 ":" $6 ":" $7] = 1
        } else {
          missed[metric] += 1
        }
      }
      END {
        for (line_key in missed_lines) {
          missed["line"] += 1
        }
        for (branch_key in missed_branches) {
          missed["branch"] += 1
        }
        printf "regions\t%d\t%s\n", missed["region"], max_regions
        printf "functions\t%d\t%s\n", missed["function"], max_functions
        printf "lines\t%d\t%s\n", missed["line"], max_lines
        printf "branches\t%d\t%s\n", missed["branch"], max_branches
      }
    ' \
    max_regions="${max_regions}" \
    max_functions="${max_functions}" \
    max_lines="${max_lines}" \
    max_branches="${max_branches}" \
    "${exclusions_path}" "${events_path}"

  rm -f "${exclusions_path}" "${events_path}"
}

validate_detailed_events_present() {
  local summary_path="${1}"

  jq --exit-status '
    def as_bool:
      if type == "boolean" then . else . != 0 end;

    def require_number($metric; $field):
      .data[0].totals[$metric][$field] as $value |
      if ($value | type) == "number" then
        $value
      else
        error("coverage summary missing numeric field: " + $metric + "." + $field)
      end;

    def missed($metric):
      (require_number($metric; "count")) as $count |
      (require_number($metric; "covered")) as $covered |
      $count - $covered;

    def require_events($metric; $missed; $events):
      if $missed > 0 and $events == 0 then
        error("coverage detail missing uncovered " + $metric + " events despite summary misses")
      else
        true
      end;

    .data[0] as $data |
    (
      [
        $data.files[]? |
        (.segments // [])[] |
        . as $segment |
        ($segment[0] // 0) as $line |
        ($segment[2] // 0) as $count |
        (($segment[3] // false) | as_bool) as $has_count |
        (($segment[4] // false) | as_bool) as $is_region_entry |
        select($line > 0 and $has_count and $count == 0 and $is_region_entry)
      ] |
      length
    ) as $region_events |
    (
      [
        ($data.functions // [])[] |
        select((.count // 0) == 0) |
        (.filenames[0] // "") as $filename |
        ((.regions[0][0]) // 0) as $line |
        select($filename != "" and $line > 0)
      ] |
      length
    ) as $function_events |
    (
      [
        $data.files[]? |
        (.segments // [])[] |
        . as $segment |
        ($segment[0] // 0) as $line |
        ($segment[2] // 0) as $count |
        (($segment[3] // false) | as_bool) as $has_count |
        select($line > 0 and $has_count and $count == 0)
      ] |
      length
    ) as $line_events |
    (
      [
        $data.files[]? |
        (.branches // [])[] |
        . as $branch |
        ($branch[0] // 0) as $line |
        [
          ($branch[4] // 0),
          ($branch[5] // 0)
        ][] as $count |
        select($line > 0 and $count == 0)
      ] |
      length
    ) as $branch_events |
    [
      require_events("regions"; missed("regions"); $region_events),
      require_events("functions"; missed("functions"); $function_events),
      require_events("lines"; missed("lines"); $line_events),
      require_events("branches"; missed("branches"); $branch_events)
    ] |
    all
  ' "${summary_path}" >/dev/null
}

build_exclusion_table() {
  local summary_path="${1}"
  local filenames_path
  local filename
  local line

  filenames_path=$(mktemp "${TMPDIR:-/tmp}/custode-coverage-files.XXXXXX")
  jq --raw-output '.data[0].files[].filename' "${summary_path}" >"${filenames_path}"
  while IFS= read -r filename; do
    if [[ ! -f "${filename}" ]]; then
      continue
    fi
    line=$(awk '
      function opens_raw_string(text, position, prefix_length, cursor, text_length, char) {
        prefix_length = 0
        if (substr(text, position, 2) == "br") {
          prefix_length = 2
        } else if (substr(text, position, 1) == "r") {
          prefix_length = 1
        } else {
          return 0
        }

        cursor = position + prefix_length
        text_length = length(text)
        raw_hashes = 0
        while (cursor <= text_length && substr(text, cursor, 1) == "#") {
          raw_hashes += 1
          cursor += 1
        }
        char = substr(text, cursor, 1)
        if (char == "\"") {
          raw_start = cursor
          return 1
        }
        return 0
      }

      function closes_raw_string(text, position, cursor, hash_index) {
        cursor = position + 1
        for (hash_index = 1; hash_index <= raw_hashes; hash_index += 1) {
          if (substr(text, cursor, 1) != "#") {
            return 0
          }
          cursor += 1
        }
        raw_end = cursor
        return 1
      }

      function starts_lifetime(text, position, next_char) {
        next_char = substr(text, position + 1, 1)
        return next_char ~ /^[[:alpha:]_]$/
      }

      function scan_line(text, cursor, text_length, char, next_char) {
        code_text = ""
        delta = 0
        cursor = 1
        text_length = length(text)
        while (cursor <= text_length) {
          char = substr(text, cursor, 1)
          next_char = substr(text, cursor + 1, 1)

          if (block_comment_depth > 0) {
            if (char == "/" && next_char == "*") {
              block_comment_depth += 1
              cursor += 2
            } else if (char == "*" && next_char == "/") {
              block_comment_depth -= 1
              cursor += 2
            } else {
              cursor += 1
            }
            continue
          }

          if (in_raw_string == 1) {
            if (char == "\"" && closes_raw_string(text, cursor)) {
              in_raw_string = 0
              cursor = raw_end
            } else {
              cursor += 1
            }
            continue
          }

          if (in_string == 1) {
            if (char == "\\") {
              cursor += 2
            } else if (char == "\"") {
              in_string = 0
              cursor += 1
            } else {
              cursor += 1
            }
            continue
          }

          if (in_char == 1) {
            if (char == "\\") {
              cursor += 2
            } else if (char == "'\''") {
              in_char = 0
              cursor += 1
            } else {
              cursor += 1
            }
            continue
          }

          if (char == "/" && next_char == "/") {
            break
          }
          if (char == "/" && next_char == "*") {
            block_comment_depth += 1
            cursor += 2
            continue
          }
          if (opens_raw_string(text, cursor)) {
            in_raw_string = 1
            cursor = raw_start + 1
            continue
          }
          if (char == "\"") {
            in_string = 1
            cursor += 1
            continue
          }
          if (char == "'\''" && starts_lifetime(text, cursor) == 0) {
            in_char = 1
            cursor += 1
            continue
          }
          if (char == "{") {
            delta += 1
          } else if (char == "}") {
            delta -= 1
          }
          code_text = code_text char
          cursor += 1
        }
      }
      in_module == 1 {
        scan_line($0)
        depth += delta
        if (depth <= 0) {
          printf "%s\t%d\t%d\n", FILENAME, start_line, NR
          in_module = 0
        }
        next
      }
      {
        scan_line($0)
      }
      code_text ~ /^[[:space:]]*mod[[:space:]]+(tests|proptests)[[:space:]]*\{/ {
        in_module = 1
        start_line = NR
        depth = delta
        if (depth <= 0) {
          printf "%s\t%d\t%d\n", FILENAME, start_line, NR
          in_module = 0
        }
        next
      }
      END {
        if (in_module == 1) {
          exit 2
        }
      }
    ' "${filename}")
    if [[ -n "${line}" ]]; then
      printf '%s\n' "${line}"
    fi
  done <"${filenames_path}"
  rm -f "${filenames_path}"
}

usage() {
  printf 'usage: %s [options] <cargo-llvm-cov-summary.json>\n' "${0}"
  printf 'options:\n'
  printf '  --exclude-test-mods\n'
  printf '  --max-missed-regions <count>\n'
  printf '  --max-missed-functions <count>\n'
  printf '  --max-missed-lines <count>\n'
  printf '  --max-missed-branches <count>\n'
}

require_count_option() {
  local option="${1}"
  local value="${2}"

  if [[ -z "${value}" ]]; then
    printf '%s requires a value\n' "${option}" >&2
    return 2
  fi

  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    printf '%s requires a non-negative integer, got: %s\n' \
      "${option}" "${value}" >&2
    return 2
  fi
}

main "${@}"
