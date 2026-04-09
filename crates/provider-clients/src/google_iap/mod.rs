use crate::{ProviderError, ProviderResult};

#[derive(Debug, Clone, Default)]
pub struct GoogleIapClient;

impl GoogleIapClient {
    pub fn verify_purchase_token(&self, token: &str) -> ProviderResult<bool> {
        if token.trim().is_empty() {
            return Err(ProviderError::Rejected(
                "google purchase token is required".to_string(),
            ));
        }
        Ok(true)
    }
}
