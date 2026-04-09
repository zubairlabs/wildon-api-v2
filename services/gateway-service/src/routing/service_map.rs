use std::env;

#[derive(Debug, Clone)]
pub struct ServiceMap {
    pub auth_grpc: String,
    pub api_clients_grpc: String,
    pub public_grpc: String,
    pub users_grpc: String,
    pub core_grpc: String,
    pub billing_grpc: String,
    pub logs_grpc: String,
    /// HTTP base URL for the chat-service (REST + WebSocket proxy target).
    pub chat_http: String,
}

impl ServiceMap {
    pub fn from_env() -> Self {
        Self {
            auth_grpc: env::var("AUTH_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string()),
            api_clients_grpc: env::var("API_CLIENTS_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:50058".to_string()),
            public_grpc: env::var("PUBLIC_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:50052".to_string()),
            users_grpc: env::var("USERS_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:50057".to_string()),
            core_grpc: env::var("CORE_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:50053".to_string()),
            billing_grpc: env::var("BILLING_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:50059".to_string()),
            logs_grpc: env::var("LOGS_GRPC_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:50054".to_string()),
            chat_http: env::var("CHAT_SERVICE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8082".to_string()),
        }
    }
}
