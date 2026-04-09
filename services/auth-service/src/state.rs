use contracts::wildon::users::v1::users_service_client::UsersServiceClient;
use redis::Client as RedisClient;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::Channel;

pub type SharedUsersClient = Arc<Mutex<UsersServiceClient<Channel>>>;

#[derive(Debug, Clone)]
pub struct AppState {
    pub issuer: String,
    pub db: PgPool,
    pub redis: Option<RedisClient>,
    pub users_client: SharedUsersClient,
    pub redis_cache_ttl_seconds: u64,
    access_ttl_public_seconds: i64,
    access_ttl_platform_seconds: i64,
    access_ttl_control_seconds: i64,
    refresh_ttl_public_seconds: i64,
    refresh_ttl_platform_seconds: i64,
    refresh_ttl_control_seconds: i64,
    absolute_session_ttl_public_seconds: i64,
    absolute_session_ttl_platform_seconds: i64,
    absolute_session_ttl_control_seconds: i64,
    inactivity_ttl_public_seconds: i64,
    inactivity_ttl_platform_seconds: i64,
    inactivity_ttl_control_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct TokenPolicyConfig {
    pub access_ttl_public_seconds: i64,
    pub access_ttl_platform_seconds: i64,
    pub access_ttl_control_seconds: i64,
    pub refresh_ttl_public_seconds: i64,
    pub refresh_ttl_platform_seconds: i64,
    pub refresh_ttl_control_seconds: i64,
    pub absolute_session_ttl_public_seconds: i64,
    pub absolute_session_ttl_platform_seconds: i64,
    pub absolute_session_ttl_control_seconds: i64,
    pub inactivity_ttl_public_seconds: i64,
    pub inactivity_ttl_platform_seconds: i64,
    pub inactivity_ttl_control_seconds: i64,
}

impl Default for TokenPolicyConfig {
    fn default() -> Self {
        Self {
            access_ttl_public_seconds: 15 * 60,
            access_ttl_platform_seconds: 10 * 60,
            access_ttl_control_seconds: 5 * 60,
            refresh_ttl_public_seconds: 30 * 24 * 60 * 60,
            refresh_ttl_platform_seconds: 14 * 24 * 60 * 60,
            refresh_ttl_control_seconds: 14 * 24 * 60 * 60,
            absolute_session_ttl_public_seconds: 90 * 24 * 60 * 60,
            absolute_session_ttl_platform_seconds: 30 * 24 * 60 * 60,
            absolute_session_ttl_control_seconds: 30 * 24 * 60 * 60,
            inactivity_ttl_public_seconds: 30 * 24 * 60 * 60,
            inactivity_ttl_platform_seconds: 14 * 24 * 60 * 60,
            inactivity_ttl_control_seconds: 7 * 24 * 60 * 60,
        }
    }
}

impl AppState {
    pub fn new(
        issuer: String,
        db: PgPool,
        redis: Option<RedisClient>,
        users_client: UsersServiceClient<Channel>,
        redis_cache_ttl_seconds: u64,
        policy: TokenPolicyConfig,
    ) -> Self {
        Self {
            issuer,
            db,
            redis,
            users_client: Arc::new(Mutex::new(users_client)),
            redis_cache_ttl_seconds,
            access_ttl_public_seconds: policy.access_ttl_public_seconds,
            access_ttl_platform_seconds: policy.access_ttl_platform_seconds,
            access_ttl_control_seconds: policy.access_ttl_control_seconds,
            refresh_ttl_public_seconds: policy.refresh_ttl_public_seconds,
            refresh_ttl_platform_seconds: policy.refresh_ttl_platform_seconds,
            refresh_ttl_control_seconds: policy.refresh_ttl_control_seconds,
            absolute_session_ttl_public_seconds: policy.absolute_session_ttl_public_seconds,
            absolute_session_ttl_platform_seconds: policy.absolute_session_ttl_platform_seconds,
            absolute_session_ttl_control_seconds: policy.absolute_session_ttl_control_seconds,
            inactivity_ttl_public_seconds: policy.inactivity_ttl_public_seconds,
            inactivity_ttl_platform_seconds: policy.inactivity_ttl_platform_seconds,
            inactivity_ttl_control_seconds: policy.inactivity_ttl_control_seconds,
        }
    }

    pub fn access_ttl_seconds(&self, aud: &str) -> i64 {
        match aud {
            "platform" => self.access_ttl_platform_seconds,
            "control" => self.access_ttl_control_seconds,
            _ => self.access_ttl_public_seconds,
        }
    }

    pub fn refresh_ttl_seconds(&self, aud: &str) -> i64 {
        match aud {
            "platform" => self.refresh_ttl_platform_seconds,
            "control" => self.refresh_ttl_control_seconds,
            _ => self.refresh_ttl_public_seconds,
        }
    }

    pub fn absolute_session_ttl_seconds(&self, aud: &str) -> i64 {
        match aud {
            "platform" => self.absolute_session_ttl_platform_seconds,
            "control" => self.absolute_session_ttl_control_seconds,
            _ => self.absolute_session_ttl_public_seconds,
        }
    }

    pub fn inactivity_ttl_seconds(&self, aud: &str) -> i64 {
        match aud {
            "platform" => self.inactivity_ttl_platform_seconds,
            "control" => self.inactivity_ttl_control_seconds,
            _ => self.inactivity_ttl_public_seconds,
        }
    }
}
