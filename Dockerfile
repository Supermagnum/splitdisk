# syntax=docker/dockerfile:1.7

# Multi-stage, pinned tag, non-root build/test image for SplitDisk Phase 1.
# All builds/tests MUST run here (scripts/test.sh). Never operate on /dev.
# Dependencies are fetched at image build time so `docker run --network none` works.

FROM docker.io/library/rust:1.85.0-bookworm AS toolchain

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt clippy \
    && cargo install cargo-deny --locked --version 0.16.3 \
    && useradd --create-home --uid 1000 --shell /bin/bash builder \
    && mkdir -p /work /tmp/cargo-target \
    && chown -R builder:builder /work /tmp/cargo-target /home/builder

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
