FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p users-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/users-service /usr/local/bin/users-service
CMD ["/usr/local/bin/users-service"]
