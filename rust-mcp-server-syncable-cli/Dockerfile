# syntax=docker/dockerfile:1

# ---- Build Stage ----
FROM rust:latest AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin mcp-sse

# ---- Runtime Stage ----
FROM debian:bookworm-slim
WORKDIR /app
# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/mcp-sse /usr/local/bin/mcp-sse
EXPOSE 8000
CMD ["/usr/local/bin/mcp-sse"]
