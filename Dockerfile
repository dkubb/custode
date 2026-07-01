# syntax=docker/dockerfile:1.7

FROM rust:1-trixie@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376 AS proxy-builder

ARG TARGETARCH

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

WORKDIR /build

RUN <<'BASH'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --no-install-recommends --yes ca-certificates musl-tools
case "${TARGETARCH}" in
  amd64) rust_target=x86_64-unknown-linux-musl ;;
  arm64) rust_target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 64 ;;
esac
mkdir --parents /tmp/custode-root/var/log/custode /tmp/custode-root/tmp
printf '%s\n' \
  'custode:x:65532:65532:custode:/nonexistent:/sbin/nologin' \
  > /tmp/custode-root/passwd
printf '%s\n' 'custode:x:65532:' > /tmp/custode-root/group
chown --recursive 65532:65532 /tmp/custode-root
apt-get autoremove --yes
rm --force --recursive /var/lib/apt/lists/*
BASH

COPY .cargo/ ./.cargo/
COPY Cargo.lock Cargo.toml rust-toolchain.toml ./
COPY src/ ./src/

RUN <<'BASH'
case "${TARGETARCH}" in
  amd64) rust_target=x86_64-unknown-linux-musl ;;
  arm64) rust_target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 64 ;;
esac
rustup target add "${rust_target}"
cargo build --locked --release --bin custode-proxy --target "${rust_target}"
cp "target/${rust_target}/release/custode-proxy" /tmp/custode-proxy
BASH

FROM scratch AS proxy

COPY --from=proxy-builder /tmp/custode-proxy /custode-proxy
COPY --from=proxy-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=proxy-builder /tmp/custode-root/passwd /etc/passwd
COPY --from=proxy-builder /tmp/custode-root/group /etc/group
COPY --from=proxy-builder --chown=65532:65532 /tmp/custode-root/var/log/custode /var/log/custode
COPY --from=proxy-builder --chown=65532:65532 /tmp/custode-root/tmp /tmp

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/custode-proxy"]
CMD ["serve"]
HEALTHCHECK --interval=5s --timeout=5s --retries=12 \
  CMD ["/custode-proxy", "healthcheck", "--addr", "127.0.0.1:8080"]

FROM debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2 AS harness

ARG HARNESS_NPM_PACKAGES=""

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

RUN <<'BASH'
export DEBIAN_FRONTEND=noninteractive
packages=(
  bash
  ca-certificates
  curl
  git
  iproute2
  procps
)
if [[ -n "${HARNESS_NPM_PACKAGES}" ]]; then
  packages+=(
    nodejs
    npm
  )
fi
apt-get update
apt-get install --no-install-recommends --yes "${packages[@]}"
groupadd --gid 1000 harness
useradd \
  --create-home \
  --gid 1000 \
  --home-dir /home/harness \
  --shell /bin/bash \
  --uid 1000 \
  harness
mkdir --parents /opt/harness/npm
npm_config_prefix=/opt/harness/npm
if [[ -n "${HARNESS_NPM_PACKAGES}" ]]; then
  read -r -a harness_npm_packages <<< "${HARNESS_NPM_PACKAGES}"
  npm install \
    --global \
    --omit=dev \
    --prefix "${npm_config_prefix}" \
    "${harness_npm_packages[@]}"
fi
mkdir --parents /workspace
chown --recursive 1000:1000 /home/harness /opt/harness /workspace
apt-get autoremove --yes
rm --force --recursive /var/lib/apt/lists/*
BASH

USER 1000:1000
WORKDIR /workspace
ENV HOME=/home/harness
ENV PATH=/opt/harness/npm/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CMD ["bash", "-c", "sleep infinity"]
HEALTHCHECK --interval=5s --timeout=5s --retries=12 \
  CMD ["test", "-d", "/workspace"]
