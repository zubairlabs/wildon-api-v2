use rand::Rng;
use sqlx::PgPool;
use tonic::Status;

/// Generate a unique human-readable reference like `SUB-K8P2X9Q1`.
/// Retries up to 5 times on collision against the given table.
pub async fn generate_unique_ref(db: &PgPool, prefix: &str, table: &str) -> Result<String, Status> {
    for _ in 0..5 {
        let code: String = rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(8)
            .map(|b| (b as char).to_ascii_uppercase())
            .collect();
        let candidate = format!("{prefix}-{code}");

        let query = format!("SELECT 1 FROM {table} WHERE display_ref = $1");
        let exists: Option<(i32,)> = sqlx::query_as(&query)
            .bind(&candidate)
            .fetch_optional(db)
            .await
            .map_err(|e| Status::internal(format!("display_ref uniqueness check failed: {e}")))?;

        if exists.is_none() {
            return Ok(candidate);
        }
    }
    Err(Status::internal(format!(
        "failed to generate unique {prefix}-* ref after 5 attempts"
    )))
}
