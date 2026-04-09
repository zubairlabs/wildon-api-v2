FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p control-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/control-service /usr/local/bin/control-service
CMD ["/usr/local/bin/control-service"]
