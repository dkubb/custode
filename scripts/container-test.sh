#!/usr/bin/env bash
# Container tests for the Custode Compose topology.
#
# Proves the ARCHITECTURE.md Section 16 container properties:
# - both images build;
# - /custode-proxy in the proxy image is statically linked;
# - the composition comes up with a healthy proxy;
# - the proxy publishes no ports to the host;
# - the harness cannot reach an external URL directly, tested from inside
#   the harness container;
# - the harness can reach the gateway on the internal network.
set -o errexit -o errtrace -o nounset -o pipefail

export CUSTODE_UPSTREAM_ORIGIN="${CUSTODE_UPSTREAM_ORIGIN:-https://api.anthropic.com}"
export CUSTODE_ALLOWED_OPERATIONS="${CUSTODE_ALLOWED_OPERATIONS:-POST:prefix:/v1/messages,GET:prefix:/v1/models}"

cleanup() {
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> docker compose build proxy harness"
docker compose build proxy harness

echo "==> static linkage of /custode-proxy"
container_id=$(docker create custode-proxy:local)
binary_dir=$(mktemp -d)
docker cp "${container_id}:/custode-proxy" "${binary_dir}/custode-proxy"
docker rm "${container_id}" >/dev/null
file "${binary_dir}/custode-proxy" | grep -E 'static-pie linked|statically linked'
rm -rf "${binary_dir}"

echo "==> docker compose up with healthy proxy"
docker compose up --detach --wait

echo "==> proxy publishes no ports to the host"
published=$(docker compose port proxy 8080 2>/dev/null || true)
case "${published}" in
  # `docker compose port` reports port 0 when nothing is published.
  "" | *:0) ;;
  *)
    echo "FAIL: proxy port 8080 is published to the host: ${published}" >&2
    exit 1
    ;;
esac

echo "==> harness cannot reach an external URL directly"
if docker compose exec -T harness curl --silent --max-time 5 https://example.com >/dev/null 2>&1; then
  echo "FAIL: harness reached an external URL directly" >&2
  exit 1
fi

echo "==> harness reaches the gateway on the internal network"
status=$(docker compose exec -T harness curl --silent --output /dev/null \
  --write-out '%{http_code}' --max-time 5 http://proxy:8080/denied)
case "${status}" in
  400 | 403 | 405) ;;
  *)
    echo "FAIL: unexpected gateway status ${status}" >&2
    exit 1
    ;;
esac

echo "PASS: container tests succeeded"
