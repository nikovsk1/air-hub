# Multi-stage Dockerfile for air-alert-hub-rs
# Targets: linux/arm/v7 (SONOFF iHost 32-bit), linux/arm64, linux/amd64

# ================= Stage 1: Build =================
FROM rust:1.82-alpine AS builder

WORKDIR /usr/src/app

# Install build dependencies for static linking
RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static gcc g++ make perl

# Pre-cache dependencies
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Copy source code and assets
COPY src ./src
COPY static ./static
COPY data_defaults ./data_defaults

# Build final optimized binary
RUN touch src/main.rs && cargo build --release

# ================= Stage 2: Minimal Runtime =================
FROM alpine:3.20 AS runner

# Install timezone data and root certificates
RUN apk add --no-cache tzdata ca-certificates

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
