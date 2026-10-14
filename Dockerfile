FROM rust:1.88-bookworm AS builder

WORKDIR /build
COPY . .

RUN cargo build --release --package forculus-cli

FROM debian:bookworm-slim

LABEL io.modelcontextprotocol.server.name="io.github.bpolania/forculus"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/forculus /usr/local/bin/forculus

RUN useradd --create-home --shell /bin/bash forculus
USER forculus
WORKDIR /home/forculus

EXPOSE 8080 3000

ENTRYPOINT ["forculus"]
CMD ["proxy", "start"]
