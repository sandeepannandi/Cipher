FROM rust:1.97-slim-bookworm AS builder

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Cache dependencies by building a dummy project first
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || echo "info: dependency pre-build done"

COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/cipher-ai /usr/local/bin/cipher

ENTRYPOINT ["cipher"]
CMD ["--help"]
