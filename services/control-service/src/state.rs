use contracts::wildon::api_clients::v1::api_clients_service_client::ApiClientsServiceClient;
use contracts::wildon::auth::v1::auth_service_client::AuthServiceClient;
use contracts::wildon::billing::v1::billing_service_client::BillingServiceClient;
use contracts::wildon::core::v1::core_service_client::CoreServiceClient;
use contracts::wildon::logs::v1::logs_service_client::LogsServiceClient;
use contracts::wildon::users::v1::users_service_client::UsersServiceClient;
use redis::Client as RedisClient;
use sqlx::PgPool;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::Mutex;
use tonic::transport::Channel;

#[derive(Debug, Clone)]
pub struct AdminUserRecord {
    pub user_id: String,
    pub active: bool,
    pub updated_at: i64,
}

#[derive(Debug, Default)]
pub struct ControlData {
    pub users: HashMap<String, AdminUserRecord>,
    pub roles: HashMap<String, Vec<String>>,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub data: Arc<Mutex<ControlData>>,
    pub core_client: Arc<Mutex<CoreServiceClient<Channel>>>,
    pub billing_client: Arc<Mutex<BillingServiceClient<Channel>>>,
    pub logs_client: Arc<Mutex<LogsServiceClient<Channel>>>,
    pub auth_client: Arc<Mutex<AuthServiceClient<Channel>>>,
    pub users_client: Arc<Mutex<UsersServiceClient<Channel>>>,
    pub api_clients_client: Arc<Mutex<ApiClientsServiceClient<Channel>>>,
    pub redis: Option<RedisClient>,
    pub expected_issuer: String,
    pub bootstrap_token: String,
    pub internal_web_token: String,
    pub allowed_hosts: HashSet<String>,
    pub device_gateway_base_url: String,
    pub device_gateway_internal_token: String,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub fn new(
        db: PgPool,
        core_client: CoreServiceClient<Channel>,
        billing_client: BillingServiceClient<Channel>,
        logs_client: LogsServiceClient<Channel>,
        auth_client: AuthServiceClient<Channel>,
        users_client: UsersServiceClient<Channel>,
        api_clients_client: ApiClientsServiceClient<Channel>,
        redis: Option<RedisClient>,
        expected_issuer: String,
        bootstrap_token: String,
        internal_web_token: String,
        allowed_hosts: HashSet<String>,
        device_gateway_base_url: String,
        device_gateway_internal_token: String,
    ) -> Self {
        Self {
            db,
            data: Arc::new(Mutex::new(ControlData::default())),
            core_client: Arc::new(Mutex::new(core_client)),
            billing_client: Arc::new(Mutex::new(billing_client)),
            logs_client: Arc::new(Mutex::new(logs_client)),
            auth_client: Arc::new(Mutex::new(auth_client)),
            users_client: Arc::new(Mutex::new(users_client)),
            api_clients_client: Arc::new(Mutex::new(api_clients_client)),
            redis,
            expected_issuer,
            bootstrap_token,
            internal_web_token,
            allowed_hosts,
            device_gateway_base_url,
            device_gateway_internal_token,
            http_client: reqwest::Client::new(),
        }
    }
}
