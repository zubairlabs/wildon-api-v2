#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDimension {
    User,
    Client,
}

impl RateLimitDimension {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Client => "client",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteId {
    pub method: String,
    pub template: String,
}

impl RouteId {
    pub fn new(method: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            method: method.into().to_uppercase(),
            template: template.into(),
        }
    }

    pub fn as_key(&self) -> String {
        format!("{}:{}", self.method, self.template)
    }
}

pub fn user_endpoint_key(user_id: &str, route_id: &RouteId) -> String {
    format!("rl:ept:u:{user_id}:{}", route_id.as_key())
}

pub fn client_endpoint_key(client_id: &str, route_id: &RouteId) -> String {
    format!("rl:ept:c:{client_id}:{}", route_id.as_key())
}
