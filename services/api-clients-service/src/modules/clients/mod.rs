use contracts::wildon::api_clients::v1::{
    ClientEnvironment, ClientPolicy, ClientStatus, ClientType,
};

pub fn default_policy(client_id: &str) -> ClientPolicy {
    ClientPolicy {
        client_id: client_id.to_string(),
        client_type: ClientType::Public as i32,
        status: ClientStatus::Active as i32,
        environment: ClientEnvironment::Prod as i32,
        allowed_audiences: vec!["public".to_string()],
        rate_limit_profile: "public_mobile_v1".to_string(),
        min_app_version: String::new(),
        default_user_rpm: 60,
        default_client_rpm: 5000,
        route_overrides: Vec::new(),
        surface: "public".to_string(),
        is_version_enforced: false,
        max_app_version: String::new(),
        allowed_origins: Vec::new(),
        ip_allowlist: Vec::new(),
        require_mtls: false,
        user_rate_policy: "user_public_v1".to_string(),
        client_safety_policy: "client_mobile_prod_high".to_string(),
        has_active_secret: false,
    }
}
