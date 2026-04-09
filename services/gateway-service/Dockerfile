FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p gateway-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/gateway-service /usr/local/bin/gateway-service
CMD ["/usr/local/bin/gateway-service"]
