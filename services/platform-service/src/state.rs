use crate::modules::shared::SharedClients;
use contracts::wildon::core::v1::core_service_client::CoreServiceClient;
use contracts::wildon::logs::v1::logs_service_client::LogsServiceClient;
use redis::Client as RedisClient;
use sqlx::PgPool;
use tonic::transport::Channel;

#[derive(Clone)]
pub struct AppState {
    pub shared_clients: SharedClients,
    pub db: PgPool,
    pub expected_issuer: String,
    pub redis: Option<RedisClient>,
}

impl AppState {
    pub fn new(
        core_client: CoreServiceClient<Channel>,
        logs_client: LogsServiceClient<Channel>,
        db: PgPool,
        expected_issuer: String,
        redis: Option<RedisClient>,
    ) -> Self {
        Self {
            shared_clients: SharedClients::new(core_client, logs_client),
            db,
            expected_issuer,
            redis,
        }
    }
}
