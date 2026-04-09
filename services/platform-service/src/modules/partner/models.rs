use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateTicketRequest {
    pub user_id: String,
    pub subject: String,
    pub message: String,
    pub contact_email: String,
}

#[derive(Debug, Deserialize)]
pub struct AddReplyRequest {
    pub author: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ReplyResponse {
    pub author: String,
    pub message: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct TicketResponse {
    pub ticket_id: String,
    pub user_id: String,
    pub subject: String,
    pub message: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub replies: Vec<ReplyResponse>,
}

#[derive(Debug, Serialize)]
pub struct PartnerDashboardResponse {
    pub open_tickets: u64,
    pub closed_tickets: u64,
    pub total_tickets: u64,
    pub flagged_content_count: u64,
    pub partner_alerts_count: u64,
    pub generated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct PartnerReportingSummaryResponse {
    pub total_tickets: u64,
    pub responded_tickets: u64,
    pub outstanding_tickets: u64,
    pub generated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct PartnerSettingsResponse {
    pub notifications_enabled: bool,
    pub alert_email: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePartnerSettingsRequest {
    pub notifications_enabled: bool,
    pub alert_email: String,
}
