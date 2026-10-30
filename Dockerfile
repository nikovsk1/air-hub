# Multi-stage Dockerfile for air-alert-hub-rs
# Targets: linux/arm/v7 (SONOFF iHost 32-bit), linux/arm64, linux/amd64

# ================= Stage 1: Build =================
FROM rust:1.82-slim-bookworm AS builder

WORKDIR /usr/src/app

# Install all necessary build tools and libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    ca-certificates \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files directly
COPY Cargo.toml ./
COPY src ./src
COPY static ./static
COPY data_defaults ./data_defaults

# Build optimized release binary
RUN cargo build --release

# ================= Stage 2: Minimal Runtime =================
FROM debian:bookworm-slim AS runner

# Install timezone data, root certificates and SSL runtime libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /usr/src/app/target/release/air-alert-hub-rs /app/air-alert-hub-rs

# Copy static assets and data defaults
COPY --from=builder /usr/src/app/static /app/static
COPY --from=builder /usr/src/app/data_defaults /app/data_defaults

# Setup persistent volume directory
VOLUME ["/app/data"]

ENV PORT=8088 \
    DATA_DIR=/app/data \
    DATA_DEFAULTS_DIR=/app/data_defaults \
    DANGER_RADIUS_KM=35.0 \
    RUST_LOG=info

EXPOSE 8088

ENTRYPOINT ["/app/air-alert-hub-rs"]
