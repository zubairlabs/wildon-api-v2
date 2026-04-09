FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p storage-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/storage-service /usr/local/bin/storage-service
CMD ["/usr/local/bin/storage-service"]
