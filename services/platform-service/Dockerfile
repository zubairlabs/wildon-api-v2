FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p platform-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/platform-service /usr/local/bin/platform-service
CMD ["/usr/local/bin/platform-service"]
