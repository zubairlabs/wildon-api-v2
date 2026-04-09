use crate::{ProviderError, ProviderResult};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct StripeWebhookVerifier {
    webhook_secret: Option<String>,
    tolerance_seconds: i64,
}

impl StripeWebhookVerifier {
    /// Load webhook secret from environment.
    ///
    /// Checks `STRIPE_MODE` (default: "test") to pick the right secret:
    ///   - test → `STRIPE_TEST_WEBHOOK_SECRET`
    ///   - live → `STRIPE_LIVE_WEBHOOK_SECRET`
    ///
    /// Falls back to `STRIPE_WEBHOOK_SECRET` if the mode-specific var isn't set.
    pub fn from_env() -> Self {
        let mode = std::env::var("STRIPE_MODE")
            .unwrap_or_else(|_| "test".to_string())
            .to_ascii_lowercase();

        let webhook_secret = match mode.as_str() {
            "live" | "production" => std::env::var("STRIPE_LIVE_WEBHOOK_SECRET")
                .or_else(|_| std::env::var("STRIPE_WEBHOOK_SECRET"))
                .ok()
                .filter(|s| !s.is_empty()),
            _ => std::env::var("STRIPE_TEST_WEBHOOK_SECRET")
                .or_else(|_| std::env::var("STRIPE_WEBHOOK_SECRET"))
                .ok()
                .filter(|s| !s.is_empty()),
        };

        let tolerance_key = match mode.as_str() {
            "live" | "production" => "STRIPE_LIVE_WEBHOOK_TOLERANCE_SECONDS",
            _ => "STRIPE_TEST_WEBHOOK_TOLERANCE_SECONDS",
        };

        let tolerance_seconds = std::env::var(tolerance_key)
            .or_else(|_| std::env::var("STRIPE_WEBHOOK_TOLERANCE_SECONDS"))
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(300);

        Self {
            webhook_secret,
            tolerance_seconds,
        }
    }

    pub fn verify(
        &self,
        signature: &str,
        payload_json: &str,
        fallback_event_id: &str,
    ) -> ProviderResult<String> {
        if self.webhook_secret.is_none() {
            // In local/dev, allow webhook flow without configured secret.
            return Ok(fallback_event_id.to_string());
        }

        if signature.trim().is_empty() {
            return Err(ProviderError::Rejected(
                "missing stripe signature".to_string(),
            ));
        }
        if payload_json.trim().is_empty() {
            return Err(ProviderError::Rejected(
                "missing stripe payload".to_string(),
            ));
        }

        let parsed = parse_signature_header(signature)?;
        let now = now_unix_seconds();
        if (now - parsed.timestamp).abs() > self.tolerance_seconds {
            return Err(ProviderError::Rejected(
                "stripe signature timestamp is outside tolerance window".to_string(),
            ));
        }

        let signed_payload = format!("{}.{}", parsed.timestamp, payload_json);
        let secret = self
            .webhook_secret
            .as_ref()
            .ok_or(ProviderError::Misconfigured("STRIPE_WEBHOOK_SECRET"))?;

        for candidate in parsed.v1_signatures {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .map_err(|_| ProviderError::Misconfigured("invalid stripe webhook secret"))?;
            mac.update(signed_payload.as_bytes());
            if mac.verify_slice(&candidate).is_ok() {
                return Ok(fallback_event_id.to_string());
            }
        }

        Err(ProviderError::Rejected(
            "stripe signature verification failed".to_string(),
        ))
    }
}

impl Default for StripeWebhookVerifier {
    fn default() -> Self {
        Self::from_env()
    }
}

#[derive(Debug)]
struct ParsedStripeSignature {
    timestamp: i64,
    v1_signatures: Vec<Vec<u8>>,
}

fn parse_signature_header(raw_signature: &str) -> ProviderResult<ParsedStripeSignature> {
    let mut timestamp: Option<i64> = None;
    let mut signatures = Vec::new();

    for part in raw_signature.split(',') {
        let trimmed = part.trim();
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        match key.trim() {
            "t" => {
                timestamp = value.trim().parse::<i64>().ok();
            }
            "v1" => {
                let decoded = hex::decode(value.trim()).map_err(|_| {
                    ProviderError::Rejected("malformed stripe v1 signature".to_string())
                })?;
                signatures.push(decoded);
            }
            _ => {}
        }
    }

    let timestamp = timestamp.ok_or_else(|| {
        ProviderError::Rejected("missing timestamp in stripe signature".to_string())
    })?;
    if signatures.is_empty() {
        return Err(ProviderError::Rejected(
            "missing v1 signature in stripe signature".to_string(),
        ));
    }

    Ok(ParsedStripeSignature {
        timestamp,
        v1_signatures: signatures,
    })
}

fn now_unix_seconds() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &str, timestamp: i64, payload: &str) -> String {
        let signed_payload = format!("{timestamp}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("valid hmac secret");
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        format!("t={timestamp},v1={signature}")
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let verifier = StripeWebhookVerifier {
            webhook_secret: Some("whsec_test_secret".to_string()),
            tolerance_seconds: 300,
        };
        let timestamp = now_unix_seconds();
        let payload = r#"{"id":"evt_123"}"#;
        let signature = sign("whsec_test_secret", timestamp, payload);

        let event_id = verifier
            .verify(&signature, payload, "evt_123")
            .expect("signature should verify");
        assert_eq!(event_id, "evt_123");
    }

    #[test]
    fn verify_rejects_mismatched_signature() {
        let verifier = StripeWebhookVerifier {
            webhook_secret: Some("whsec_test_secret".to_string()),
            tolerance_seconds: 300,
        };
        let timestamp = now_unix_seconds();
        let payload = r#"{"id":"evt_123"}"#;
        let signature = sign("whsec_wrong_secret", timestamp, payload);

        let err = verifier
            .verify(&signature, payload, "evt_123")
            .expect_err("signature should fail");
        assert!(matches!(err, ProviderError::Rejected(_)));
    }

    #[test]
    fn verify_rejects_stale_signature() {
        let verifier = StripeWebhookVerifier {
            webhook_secret: Some("whsec_test_secret".to_string()),
            tolerance_seconds: 10,
        };
        let timestamp = now_unix_seconds() - 100;
        let payload = r#"{"id":"evt_123"}"#;
        let signature = sign("whsec_test_secret", timestamp, payload);

        let err = verifier
            .verify(&signature, payload, "evt_123")
            .expect_err("signature should fail");
        assert!(matches!(err, ProviderError::Rejected(_)));
    }
}
