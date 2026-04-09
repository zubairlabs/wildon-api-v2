FROM rust:1.88-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p chat-service

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/chat-service /usr/local/bin/chat-service
CMD ["/usr/local/bin/chat-service"]
