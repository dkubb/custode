#!/usr/bin/env -S bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# Checks a cargo-llvm-cov JSON summary against missed-state limits.

main() {
	local max_regions=0
	local max_functions=0
	local max_lines=0
	local max_branches=0
	local summary_path=""

	while [[ "${#}" -gt 0 ]]; do
		case "${1}" in
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

	local report
	if ! report=$(jq --raw-output '
    .data[0].totals as $totals |
    [
      [
        "regions",
        (($totals.regions.count // 0) - ($totals.regions.covered // 0)),
        $max_regions
      ],
      [
        "functions",
        (($totals.functions.count // 0) - ($totals.functions.covered // 0)),
        $max_functions
      ],
      [
        "lines",
        (($totals.lines.count // 0) - ($totals.lines.covered // 0)),
        $max_lines
      ],
      [
        "branches",
        (($totals.branches.count // 0) - ($totals.branches.covered // 0)),
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
		"${summary_path}"); then
		printf 'failed to parse coverage summary: %s\n' "${summary_path}" >&2
		return 2
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
	done <<<"${report}"

	if [[ "${failed}" -ne 0 ]]; then
		return 1
	fi

	printf 'coverage summary is within missed-state limits\n'
}

usage() {
	printf 'usage: %s [options] <cargo-llvm-cov-summary.json>\n' "${0}"
	printf 'options:\n'
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
