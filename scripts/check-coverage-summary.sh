#!/usr/bin/env -S bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# Checks a cargo-llvm-cov JSON summary for zero missed coverage states.

main() {
	if [[ "${#}" -ne 1 ]]; then
		printf 'usage: %s <cargo-llvm-cov-summary.json>\n' "${0}" >&2
		return 2
	fi

	local summary_path="${1}"
	if [[ ! -f "${summary_path}" ]]; then
		printf 'coverage summary not found: %s\n' "${summary_path}" >&2
		return 2
	fi

	local report
	if ! report=$(jq --raw-output '
    .data[0].totals as $totals |
    [
      ["regions", (($totals.regions.count // 0) - ($totals.regions.covered // 0))],
      ["functions", (($totals.functions.count // 0) - ($totals.functions.covered // 0))],
      ["lines", (($totals.lines.count // 0) - ($totals.lines.covered // 0))],
      ["branches", (($totals.branches.count // 0) - ($totals.branches.covered // 0))]
    ] |
    .[] |
    @tsv
  ' "${summary_path}"); then
		printf 'failed to parse coverage summary: %s\n' "${summary_path}" >&2
		return 2
	fi

	local failed=0
	local metric
	local missed
	while IFS=$'\t' read -r metric missed; do
		if [[ "${missed}" != "0" ]]; then
			printf 'coverage metric %s has %s missed states\n' "${metric}" "${missed}" >&2
			failed=1
		fi
	done <<<"${report}"

	if [[ "${failed}" -ne 0 ]]; then
		return 1
	fi

	printf 'coverage summary has zero missed regions, functions, lines, and branches\n'
}

main "${@}"
