#!/usr/bin/env -S -u BASHOPTS -u BASH_ENV -u CDPATH -u GLOBIGNORE -u SHELLOPTS bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# shellcheck shell=bash
# Runs cargo with the Rust toolchain pinned in rust-toolchain.toml.

main() {
  local repository_root
  local toolchain_file
  local channel
  local toolchain_cargo
  local toolchain_bin

  repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
  toolchain_file="${repository_root}/rust-toolchain.toml"

  channel=$(
    awk -F '"' '
      /^[[:space:]]*channel[[:space:]]*=/ {
        print $2
        found = 1
        exit
      }
      END {
        if (found != 1) {
          exit 1
        }
      }
    ' "${toolchain_file}"
  ) || {
    printf 'could not read pinned Rust toolchain from %s\n' "${toolchain_file}" >&2
    return 2
  }

  toolchain_cargo=$(rustup which --toolchain "${channel}" cargo)
  toolchain_bin=${toolchain_cargo%/*}

  PATH="${toolchain_bin}:${PATH}" exec "${toolchain_cargo}" "${@}"
}

main "${@}"
