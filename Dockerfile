# syntax=docker/dockerfile:1.7

# Multi-stage, pinned tag, non-root build/test image for SplitDisk.
# All builds/tests MUST run here (scripts/test.sh). Never operate on /dev.
# Dependencies are fetched at image build time so `docker run --network none` works.
# Phase 4: build GRUB / kernel / CCID from vendor/ (read-only) into /tmp caches.
# e2fsprogs: mke2fs + debugfs -w + fsck.ext4 -n (Phase 3 option C).

FROM docker.io/library/rust:1.85.0-bookworm AS toolchain

USER root
# All apt packages pinned to bookworm candidate versions (queried 2026-09-22).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        pkg-config=1.8.1-1 \
        e2fsprogs=1.47.0-2+b2 \
        gcc=4:12.2.0-3 \
        make=4.3-4.1 \
        bison=2:3.8.2+dfsg-1+b1 \
        flex=2.6.4-8.2 \
        bc=1.07.1-3+b1 \
        libelf-dev=0.188-2.1 \
        libssl-dev=3.0.20-1~deb12u2 \
        autoconf=2.71-3 \
        automake=1:1.16.5-1.3 \
        autoconf-archive=20220903-3 \
        autopoint=0.21-12 \
        gettext=0.21-12 \
        python3=3.11.2-1+b1 \
        gawk=1:5.2.1-2 \
        xz-utils=5.4.1-1+deb12u2 \
        rsync=3.2.7-1+deb12u6 \
        patch=2.7.6-7 \
        meson=1.0.1-5 \
        ninja-build=1.11.1-2~deb12u1 \
        libpcsclite-dev=1.9.9-2 \
        libusb-1.0-0-dev=2:1.0.26-1 \
        libfreetype6-dev=2.12.1+dfsg-5+deb12u4 \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt clippy \
    && cargo install cargo-deny --locked --version 0.16.3 \
    && useradd --create-home --uid 1000 --shell /bin/bash builder \
    && mkdir -p /work /tmp/cargo-target \
    && chown -R builder:builder /work /tmp/cargo-target /home/builder \
    && fsck.ext4 -V \
    && meson --version \
    && ninja --version

USER builder
WORKDIR /work
ENV CARGO_HOME=/home/builder/.cargo
ENV CARGO_TARGET_DIR=/tmp/cargo-target
ENV PATH="/home/builder/.cargo/bin:/usr/local/cargo/bin:${PATH}"

# Prefetch crates so test containers can run with --network none.
COPY --chown=builder:builder Cargo.toml Cargo.lock rust-toolchain.toml deny.toml ./
COPY --chown=builder:builder crates ./crates
RUN cargo fetch --locked

FROM toolchain AS test
WORKDIR /work
CMD ["bash", "scripts/docker-test-inner.sh"]
