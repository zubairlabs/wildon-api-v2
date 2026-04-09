use crate::state::ControlData;
use chrono::Utc;

#[derive(Debug, Clone)]
pub struct ControlDashboardSummary {
    pub managed_users: u64,
    pub active_users: u64,
    pub total_role_bindings: u64,
    pub revenue_cents_24h: i64,
    pub active_subscriptions: u64,
    pub generated_at: i64,
}

pub fn summarize(data: &ControlData) -> ControlDashboardSummary {
    let managed_users = data.users.len() as u64;
    let active_users = data.users.values().filter(|user| user.active).count() as u64;
    let total_role_bindings = data.roles.values().map(|roles| roles.len() as u64).sum();

    ControlDashboardSummary {
        managed_users,
        active_users,
        total_role_bindings,
        revenue_cents_24h: 0,
        active_subscriptions: 0,
        generated_at: Utc::now().timestamp(),
    }
}
