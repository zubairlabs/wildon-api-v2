pub mod apple_iap;
pub mod fcm;
pub mod google_iap;
pub mod openai;
pub mod sendgrid;
pub mod stripe;
pub mod twilio;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationChannel {
    Email,
    Sms,
    Push,
}

#[derive(Debug, Clone)]
pub struct NotificationPayload {
    pub destination: String,
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct NotificationReceipt {
    pub provider: &'static str,
    pub external_id: String,
}

#[derive(Debug, Clone)]
pub struct AiCompletion {
    pub text: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub cost_micros: u64,
    pub model: String,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider is not configured: {0}")]
    Misconfigured(&'static str),
    #[error("provider rejected request: {0}")]
    Rejected(String),
    #[error("provider transport error: {0}")]
    Transport(String),
}

pub type ProviderResult<T> = Result<T, ProviderError>;

pub trait NotificationProvider {
    fn provider_name(&self) -> &'static str;
    fn send(
        &self,
        channel: NotificationChannel,
        payload: &NotificationPayload,
    ) -> ProviderResult<NotificationReceipt>;
}
