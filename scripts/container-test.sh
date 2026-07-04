#!/usr/bin/env -S bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# Container tests for the Custode Compose topology.
#
# Proves the ARCHITECTURE.md Section 16 container properties:
# - both images build;
# - /custode-proxy in the proxy image is statically linked;
# - the composition comes up with a healthy proxy;
# - the proxy publishes no ports to the host;
# - the harness is attached only to Docker-internal networks;
# - the harness cannot reach an external URL directly, tested from inside
#   the harness container;
# - the harness cannot reach an external raw IP over HTTP directly;
# - the harness can reach the gateway on the internal network;
# - the proxy audit log is valid NDJSON with monotonic request IDs.

export CUSTODE_UPSTREAM_ORIGIN="${CUSTODE_UPSTREAM_ORIGIN:-https://api.anthropic.com}"
export CUSTODE_ALLOWED_OPERATIONS="${CUSTODE_ALLOWED_OPERATIONS:-POST:prefix:/v1/messages,GET:prefix:/v1/models}"
export COMPOSE_PROJECT_NAME="custode_container_test_$$"

readonly TAP_TEST_COUNT=9

test_number=0
failed=0

cleanup() {
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup_static_artifacts() {
  local container_id="${1}"
  local binary_dir="${2}"

  if [[ -n "${container_id}" ]]; then
    docker rm "${container_id}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${binary_dir}" ]]; then
    rm -rf "${binary_dir}"
  fi
}

static_linkage() {
  local container_id=""
  local binary_dir=""
  local linkage

  if ! container_id=$(docker create custode-proxy:local); then
    return 1
  fi

  if ! binary_dir=$(mktemp -d); then
    cleanup_static_artifacts "${container_id}" "${binary_dir}"
    return 1
  fi

  if ! docker cp "${container_id}:/custode-proxy" "${binary_dir}/custode-proxy"; then
    cleanup_static_artifacts "${container_id}" "${binary_dir}"
    return 1
  fi

  if ! docker rm "${container_id}" >/dev/null; then
    cleanup_static_artifacts "${container_id}" "${binary_dir}"
    return 1
  fi
  container_id=""

  if ! linkage=$(file "${binary_dir}/custode-proxy"); then
    cleanup_static_artifacts "${container_id}" "${binary_dir}"
    return 1
  fi
  printf '%s\n' "${linkage}"

  if ! grep -E "static-pie linked|statically linked" <<<"${linkage}" >/dev/null; then
    cleanup_static_artifacts "${container_id}" "${binary_dir}"
    return 1
  fi

  cleanup_static_artifacts "${container_id}" "${binary_dir}"
}

proxy_publishes_no_ports() {
  local container_id
  local published

  if ! container_id=$(docker compose ps --quiet proxy); then
    return 1
  fi

  if [[ -z "${container_id}" ]]; then
    printf "proxy container was not found\n" >&2
    return 1
  fi

  if ! published=$(docker inspect --format '{{range $port, $bindings := .NetworkSettings.Ports}}{{if $bindings}}{{$port}} {{end}}{{end}}' "${container_id}"); then
    return 1
  fi

  if [[ -n "${published}" ]]; then
    printf "proxy publishes host ports: %s\n" "${published}" >&2
    return 1
  fi
}

harness_networks_are_internal_only() {
  local container_id
  local internal
  local network_id
  local network_ids=()

  if ! container_id=$(docker compose ps --quiet harness); then
    return 1
  fi

  if [[ -z "${container_id}" ]]; then
    printf "harness container was not found\n" >&2
    return 1
  fi

  while IFS= read -r network_id; do
    if [[ -n "${network_id}" ]]; then
      network_ids+=("${network_id}")
    fi
  done < <(docker inspect --format '{{range .NetworkSettings.Networks}}{{.NetworkID}}{{"\n"}}{{end}}' "${container_id}")

  if [[ "${#network_ids[@]}" -ne 1 ]]; then
    printf "expected harness to have exactly 1 network, found %d\n" "${#network_ids[@]}" >&2
    return 1
  fi

  if ! internal=$(docker network inspect --format '{{.Internal}}' "${network_ids[0]}"); then
    return 1
  fi

  if [[ "${internal}" != "true" ]]; then
    printf "harness network %s is not internal\n" "${network_ids[0]}" >&2
    return 1
  fi
}

harness_cannot_reach_external() {
  if docker compose exec -T harness curl --silent --max-time 5 https://example.com >/dev/null 2>&1; then
    printf "harness reached an external URL directly\n" >&2
    return 1
  fi
}

harness_cannot_reach_raw_ip_http() {
  if docker compose exec -T harness curl --silent --max-time 5 http://1.1.1.1/ >/dev/null 2>&1; then
    printf "harness reached a raw IP over HTTP directly\n" >&2
    return 1
  fi
}

harness_reaches_gateway() {
  local status

  if ! status=$(docker compose exec -T harness curl --silent --output /dev/null \
    --write-out '%{http_code}' --max-time 5 http://proxy:8080/denied); then
    return 1
  fi

  case "${status}" in
    400 | 403 | 405) ;;
    *)
      printf "unexpected gateway status %s\n" "${status}" >&2
      return 1
      ;;
  esac
}

proxy_audit_log_is_valid() {
  local audit_dir=""
  local audit_log
  local container_id
  local event_count
  local status=0

  if ! container_id=$(docker compose ps --quiet proxy); then
    return 1
  fi

  if [[ -z "${container_id}" ]]; then
    printf "proxy container was not found\n" >&2
    return 1
  fi

  if ! audit_dir=$(mktemp -d); then
    return 1
  fi
  audit_log="${audit_dir}/proxy.ndjson"

  if ! docker cp "${container_id}:/var/log/custode/proxy.ndjson" "${audit_log}"; then
    status=1
  elif ! scripts/verify-audit-log.sh "${audit_log}"; then
    status=1
  elif ! event_count=$(jq -s 'length' <"${audit_log}"); then
    status=1
  elif [[ "${event_count}" -lt 1 ]]; then
    printf "proxy audit log has no events\n" >&2
    status=1
  fi

  rm -rf "${audit_dir}"
  return "${status}"
}

tap_diag() {
  local line

  if [[ -z "${1}" ]]; then
    return 0
  fi

  while IFS= read -r line; do
    printf '# %s\n' "${line}"
  done <<<"${1}"
}

run_test() {
  local name="${1}"
  local output
  local status

  shift
  test_number=$((test_number + 1))

  if output="$("$@" 2>&1)"; then
    printf 'ok %d - %s\n' "${test_number}" "${name}"
    return 0
  fi

  status="${?}"
  printf 'not ok %d - %s\n' "${test_number}" "${name}"
  printf '# exit status: %d\n' "${status}"
  tap_diag "${output}"
  failed=1
}

printf 'TAP version 13\n'
printf '1..%d\n' "${TAP_TEST_COUNT}"

run_test "docker compose build proxy harness" docker compose build proxy harness

run_test "static linkage of /custode-proxy" static_linkage

run_test "docker compose up with healthy proxy" docker compose up --detach --wait

run_test "proxy publishes no ports to the host" proxy_publishes_no_ports

run_test "harness networks are internal-only" harness_networks_are_internal_only

run_test "harness cannot reach an external URL directly" harness_cannot_reach_external

run_test "harness cannot reach a raw IP over HTTP directly" harness_cannot_reach_raw_ip_http

run_test "harness reaches the gateway on the internal network" harness_reaches_gateway

run_test "proxy audit log is valid" proxy_audit_log_is_valid

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi
