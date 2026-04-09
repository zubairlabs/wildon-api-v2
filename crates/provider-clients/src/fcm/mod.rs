use crate::{
    NotificationChannel, NotificationPayload, NotificationProvider, NotificationReceipt,
    ProviderError, ProviderResult,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct FcmClient {
    service_account_json: Option<String>,
    force_fail: bool,
}

impl FcmClient {
    pub fn from_env() -> Self {
        Self {
            service_account_json: std::env::var("FCM_SERVICE_ACCOUNT_JSON").ok(),
            force_fail: std::env::var("FCM_FORCE_FAIL")
                .map(|value| value == "1")
                .unwrap_or(false),
        }
    }
}

impl Default for FcmClient {
    fn default() -> Self {
        Self::from_env()
    }
}

impl NotificationProvider for FcmClient {
    fn provider_name(&self) -> &'static str {
        "fcm"
    }

    fn send(
        &self,
        channel: NotificationChannel,
        payload: &NotificationPayload,
    ) -> ProviderResult<NotificationReceipt> {
        if self.force_fail {
            return Err(ProviderError::Transport(
                "forced fcm failure for failover testing".to_string(),
            ));
        }
        if channel != NotificationChannel::Push {
            return Err(ProviderError::Rejected(
                "fcm only supports push channel".to_string(),
            ));
        }
        if self.service_account_json.is_none() {
            return Err(ProviderError::Misconfigured("FCM_SERVICE_ACCOUNT_JSON"));
        }
        if payload.destination.is_empty() {
            return Err(ProviderError::Rejected(
                "device destination is required".to_string(),
            ));
        }

        Ok(NotificationReceipt {
            provider: self.provider_name(),
            external_id: format!("fcm-{}", now_millis()),
        })
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}
