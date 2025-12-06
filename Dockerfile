FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
LABEL authors="jm"
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/arrow_server /usr/local/bin/arrow_server

RUN chmod +x /usr/local/bin/arrow_server

EXPOSE 3000
CMD ["./usr/local/bin/arrow_server"]