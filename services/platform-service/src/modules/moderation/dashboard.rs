use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ModerationDashboardResponse {
    pub flagged_content_count: u64,
    pub review_queue_count: u64,
}

pub fn summarize() -> ModerationDashboardResponse {
    ModerationDashboardResponse {
        flagged_content_count: 0,
        review_queue_count: 0,
    }
}
