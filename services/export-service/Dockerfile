FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p export-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/export-service /usr/local/bin/export-service
CMD ["/usr/local/bin/export-service"]
