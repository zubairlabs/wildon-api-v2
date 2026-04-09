#[derive(Debug, Clone)]
pub struct RateProfile {
    pub profile_name: String,
    pub default_user_rpm: i32,
    pub default_client_rpm: i32,
    pub enabled: bool,
}

impl RateProfile {
    pub fn public_default() -> Self {
        Self {
            profile_name: "public_mobile_v1".to_string(),
            default_user_rpm: 60,
            default_client_rpm: 5000,
            enabled: true,
        }
    }
}
