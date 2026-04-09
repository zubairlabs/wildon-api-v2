use crate::{
    NotificationChannel, NotificationPayload, NotificationProvider, NotificationReceipt,
    ProviderError, ProviderResult,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct TwilioClient {
    account_sid: Option<String>,
    auth_token: Option<String>,
    force_fail: bool,
}

impl TwilioClient {
    pub fn from_env() -> Self {
        Self {
            account_sid: std::env::var("TWILIO_ACCOUNT_SID").ok(),
            auth_token: std::env::var("TWILIO_AUTH_TOKEN").ok(),
            force_fail: std::env::var("TWILIO_FORCE_FAIL")
                .map(|value| value == "1")
                .unwrap_or(false),
        }
    }
}

impl Default for TwilioClient {
    fn default() -> Self {
        Self::from_env()
    }
}

impl NotificationProvider for TwilioClient {
    fn provider_name(&self) -> &'static str {
        "twilio"
    }

    fn send(
        &self,
        channel: NotificationChannel,
        payload: &NotificationPayload,
    ) -> ProviderResult<NotificationReceipt> {
        if self.force_fail {
            return Err(ProviderError::Transport(
                "forced twilio failure for failover testing".to_string(),
            ));
        }
        if channel != NotificationChannel::Sms {
            return Err(ProviderError::Rejected(
                "twilio only supports sms channel".to_string(),
            ));
        }
        if self.account_sid.is_none() || self.auth_token.is_none() {
            return Err(ProviderError::Misconfigured(
                "TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN",
            ));
        }
        if payload.destination.is_empty() {
            return Err(ProviderError::Rejected(
                "phone destination is required".to_string(),
            ));
        }

        Ok(NotificationReceipt {
            provider: self.provider_name(),
            external_id: format!("tw-{}", now_millis()),
        })
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}
