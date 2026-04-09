use crate::state::PublicData;
use chrono::Utc;

#[derive(Debug, Clone)]
pub struct DashboardSummaryData {
    pub user_id: String,
    pub devices_count: u32,
    pub trips_count: u32,
    pub media_count: u32,
    pub subscription_plan: String,
    pub subscription_status: String,
    pub ai_usage_total: u64,
    pub generated_at: i64,
}

pub fn build_summary(
    data: &PublicData,
    user_id: &str,
    subscription_plan: &str,
    subscription_status: &str,
) -> DashboardSummaryData {
    let devices_count = data
        .devices
        .get(user_id)
        .map(|devices| devices.len() as u32)
        .unwrap_or(0);

    DashboardSummaryData {
        user_id: user_id.to_string(),
        devices_count,
        trips_count: 0,
        media_count: 0,
        subscription_plan: subscription_plan.to_string(),
        subscription_status: subscription_status.to_string(),
        ai_usage_total: 0,
        generated_at: Utc::now().timestamp(),
    }
}
