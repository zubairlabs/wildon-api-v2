use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: PgPool,
}
