use chrono::Utc;

#[derive(Debug, Clone)]
pub struct UserRecordData {
    pub user_id: String,
    pub email: String,
    pub status: String,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
    pub perm_rev: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub account_number: Option<String>,
}

impl UserRecordData {
    pub fn new(user_id: String, email: String) -> Self {
        let now = Utc::now().timestamp();
        Self {
            user_id,
            email,
            status: "active".to_string(),
            roles: vec!["user".to_string()],
            scopes: vec![],
            perm_rev: 1,
            created_at: now,
            updated_at: now,
            account_number: None,
        }
    }
}
