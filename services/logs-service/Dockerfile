FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p logs-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/logs-service /usr/local/bin/logs-service
CMD ["/usr/local/bin/logs-service"]
