use crate::{
    NotificationChannel, NotificationPayload, NotificationProvider, NotificationReceipt,
    ProviderError, ProviderResult,
};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct SendgridClient {
    api_key: Option<String>,
    from_email: Option<String>,
    base_url: String,
    force_fail: bool,
}

impl SendgridClient {
    pub fn from_env() -> Self {
        Self {
            api_key: std::env::var("SENDGRID_API_KEY").ok(),
            from_email: std::env::var("SENDGRID_EMAIL_FROM").ok(),
            base_url: std::env::var("SENDGRID_BASE_URL")
                .unwrap_or_else(|_| "https://api.sendgrid.com".to_string()),
            force_fail: std::env::var("SENDGRID_FORCE_FAIL")
                .map(|value| value == "1")
                .unwrap_or(false),
        }
    }
}

impl Default for SendgridClient {
    fn default() -> Self {
        Self::from_env()
    }
}

impl NotificationProvider for SendgridClient {
    fn provider_name(&self) -> &'static str {
        "sendgrid"
    }

    fn send(
        &self,
        channel: NotificationChannel,
        payload: &NotificationPayload,
    ) -> ProviderResult<NotificationReceipt> {
        if self.force_fail {
            return Err(ProviderError::Transport(
                "forced sendgrid failure for failover testing".to_string(),
            ));
        }
        if channel != NotificationChannel::Email {
            return Err(ProviderError::Rejected(
                "sendgrid only supports email channel".to_string(),
            ));
        }

        let api_key = self
            .api_key
            .as_deref()
            .ok_or(ProviderError::Misconfigured("SENDGRID_API_KEY"))?;
        let from_email = self
            .from_email
            .as_deref()
            .ok_or(ProviderError::Misconfigured("SENDGRID_EMAIL_FROM"))?;

        if payload.destination.trim().is_empty() {
            return Err(ProviderError::Rejected(
                "email destination is required".to_string(),
            ));
        }
        let subject = sanitize_subject(&payload.subject)?;
        let message = payload.message.trim();
        if message.is_empty() {
            return Err(ProviderError::Rejected(
                "email message is required".to_string(),
            ));
        }

        let content = if looks_like_html(message) {
            json!([
                {
                    "type": "text/plain",
                    "value": strip_html_tags(message),
                },
                {
                    "type": "text/html",
                    "value": message,
                }
            ])
        } else {
            json!([
                {
                    "type": "text/plain",
                    "value": message,
                }
            ])
        };

        let endpoint = format!("{}/v3/mail/send", self.base_url.trim_end_matches('/'));
        let request_body = json!({
            "personalizations": [{
                "to": [{
                    "email": payload.destination,
                }]
            }],
            "from": {
                "email": from_email,
            },
            "subject": subject,
            "content": content,
        });

        let response = ureq::post(&endpoint)
            .set("Authorization", &format!("Bearer {api_key}"))
            .set("Content-Type", "application/json")
            .send_json(request_body);

        let external_id = match response {
            Ok(response) => response
                .header("X-Message-Id")
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("sg-{}", now_millis())),
            Err(ureq::Error::Status(status, response)) => {
                let body = response.into_string().unwrap_or_default();
                return Err(ProviderError::Transport(format!(
                    "sendgrid http {status}: {}",
                    truncate(&body, 256)
                )));
            }
            Err(ureq::Error::Transport(err)) => {
                return Err(ProviderError::Transport(format!(
                    "sendgrid transport error: {err}"
                )));
            }
        };

        Ok(NotificationReceipt {
            provider: self.provider_name(),
            external_id,
        })
    }
}

fn sanitize_subject(subject: &str) -> ProviderResult<&str> {
    let value = subject.trim();
    if value.is_empty() {
        return Err(ProviderError::Rejected(
            "email subject is required".to_string(),
        ));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(ProviderError::Rejected(
            "email subject cannot contain newlines".to_string(),
        ));
    }
    Ok(value)
}

fn looks_like_html(value: &str) -> bool {
    value.contains('<') && value.contains('>')
}

fn strip_html_tags(value: &str) -> String {
    let mut in_tag = false;
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }

    let collapsed = out
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string();
    if collapsed.is_empty() {
        " ".to_string()
    } else {
        collapsed
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out = String::with_capacity(max_chars + 3);
    for (index, ch) in value.chars().enumerate() {
        if index >= max_chars {
            break;
        }
        out.push(ch);
    }
    out.push_str("...");
    out
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}
