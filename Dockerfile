# This exact cargo-chef/Rust tag is published on Docker Hub; planner and builder must match.
FROM lukemathwalker/cargo-chef:0.1.77-rust-1.97.1 AS chef
LABEL authors="jm"
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# Debian 13 (trixie) slim, pinned by major-version tag; optionally pin to a sha256 digest for stricter reproducibility.
FROM debian:13-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libmariadb3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/arrow_server /usr/local/bin/arrow_server

RUN chmod +x /usr/local/bin/arrow_server

EXPOSE 3000
CMD ["./usr/local/bin/arrow_server"]
