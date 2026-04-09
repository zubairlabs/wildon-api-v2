use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub nats: Option<async_nats::Client>,
}

impl AppState {
    pub fn new(db: PgPool, nats: Option<async_nats::Client>) -> Self {
        Self { db, nats }
    }
}
