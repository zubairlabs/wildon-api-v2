FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p public-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/public-service /usr/local/bin/public-service
CMD ["/usr/local/bin/public-service"]
