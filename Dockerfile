# syntax=docker/dockerfile:1
# High-Performance Multi-Arch Dockerfile for Air Alert Hub (Rust Edition)
# Native Cross-Compilation via tonistiigi/xx + 100% Pure Rustls (Zero C/OpenSSL dependencies!)
# Targets: linux/arm/v7 (SONOFF iHost 32-bit), linux/arm64, linux/amd64

# ================= Stage 0: tonistiigi/xx cross-compilation tools =================
FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.5.0 AS xx

# ================= Stage 1: Native Builder ($BUILDPLATFORM) =================
FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS builder
COPY --from=xx / /

ARG TARGETPLATFORM
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

# Install host compiler tools and target C runtime for standard libc linking
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        lld \
        pkg-config \
        git \
        ca-certificates && \
    xx-apt-get update && \
    xx-apt-get install -y --no-install-recommends \
        libc6-dev \
        xx-c-essentials && \
    rustup target add $(xx-cargo --print-target-triple)

WORKDIR /usr/src/app

# 1. Dependency caching: copy Cargo manifests first
COPY Cargo.toml Cargo.lock* ./

# 2. Pre-compile pure Rust dependencies using xx-cargo for TARGETPLATFORM (cached in Docker layer)
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    xx-cargo build --release && \
    rm -rf src \
        target/$(xx-cargo --print-target-triple)/release/deps/air_alert_hub_rs* \
        target/$(xx-cargo --print-target-triple)/release/.fingerprint/air_alert_hub_rs* \
        target/$(xx-cargo --print-target-triple)/release/air-alert-hub-rs*

# 3. Copy application source code and static assets
COPY src ./src
COPY static ./static
COPY data_defaults ./data_defaults

# 4. Compile the final release binary natively and verify the target ELF architecture
RUN touch src/main.rs && \
    xx-cargo build --release && \
    xx-verify target/$(xx-cargo --print-target-triple)/release/air-alert-hub-rs && \
    cp target/$(xx-cargo --print-target-triple)/release/air-alert-hub-rs /usr/local/bin/air-alert-hub-rs

# ================= Stage 2: Minimal Target Runtime ($TARGETPLATFORM) =================
FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged runtime user and group (UID/GID 10001) for container security
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/sh -m appuser

WORKDIR /app

# Copy statically compiled binary from builder (pure Rust, no external libssl3 needed!)
COPY --from=builder /usr/local/bin/air-alert-hub-rs /app/air-alert-hub-rs

# Copy static web assets and default geographic contours
COPY --from=builder /usr/src/app/static /app/static
COPY --from=builder /usr/src/app/data_defaults /app/data_defaults

RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app /app/data

USER appuser:appgroup

VOLUME ["/app/data"]

ENV PORT=8088 \
    DATA_DIR=/app/data \
    DATA_DEFAULTS_DIR=/app/data_defaults \
    DANGER_RADIUS_KM=35.0 \
    RUST_LOG=info

EXPOSE 8088

ENTRYPOINT ["/app/air-alert-hub-rs"]
