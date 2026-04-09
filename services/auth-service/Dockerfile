FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p auth-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
CMD ["/usr/local/bin/auth-service"]
