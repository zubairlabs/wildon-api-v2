use serde::Deserialize;

pub mod grpc;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub app_name: String,
}
