# Build from repository root:
#   docker build -f docker/mesh/Dockerfile -t fubuki-mesh:test .
FROM rustlang/rust:nightly-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --bin fubuki

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/fubuki /usr/local/bin/fubuki
ENTRYPOINT ["/usr/local/bin/fubuki", "daemon", "-c", "/etc/fubuki/dc.json"]
