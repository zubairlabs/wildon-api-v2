use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub cid: String,
    pub aud: String,
    pub iss: String,
    pub realm: String,
    #[serde(default)]
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub jti: String,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default = "default_session_version")]
    pub sv: i32,
    #[serde(default = "default_perm_revision")]
    pub perm_rev: i64,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

fn default_session_version() -> i32 {
    1
}

fn default_perm_revision() -> i64 {
    1
}
