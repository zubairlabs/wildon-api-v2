use crate::state::AdminUserRecord;
use chrono::Utc;

pub fn upsert_user(user_id: &str, active: bool) -> AdminUserRecord {
    AdminUserRecord {
        user_id: user_id.to_string(),
        active,
        updated_at: Utc::now().timestamp(),
    }
}
