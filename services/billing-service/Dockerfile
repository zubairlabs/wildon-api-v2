FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p billing-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/billing-service /usr/local/bin/billing-service
COPY --from=builder /app/services/billing-service/migrations /app/migrations
CMD ["/usr/local/bin/billing-service"]
