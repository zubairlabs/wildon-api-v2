FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p api-clients-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/api-clients-service /usr/local/bin/api-clients-service
CMD ["/usr/local/bin/api-clients-service"]
