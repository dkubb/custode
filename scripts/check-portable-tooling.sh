#!/usr/bin/env -S -u BASHOPTS -u BASH_ENV -u CDPATH -u GLOBIGNORE -u SHELLOPTS bash --noprofile --norc -o errexit -o errtrace -o nounset -o pipefail
# shellcheck shell=bash
# Checks that repository tool configuration does not pin host-specific paths.

readonly CARGO_CONFIG=".cargo/config.toml"
readonly NON_PORTABLE_LLVM_PATTERN='LLVM_(COV|PROFDATA)|/(opt/homebrew|usr/local)/opt/llvm'

if grep -En "${NON_PORTABLE_LLVM_PATTERN}" "${CARGO_CONFIG}"; then
  printf 'portable-tooling: %s must not pin LLVM coverage tools to host paths\n' \
    "${CARGO_CONFIG}" >&2
  printf 'portable-tooling: rely on rust-toolchain llvm-tools-preview and cargo-llvm-cov discovery\n' >&2
  exit 1
fi
