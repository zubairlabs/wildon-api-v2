FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p core-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/core-service /usr/local/bin/core-service
CMD ["/usr/local/bin/core-service"]
