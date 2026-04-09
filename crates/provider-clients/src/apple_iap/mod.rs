use crate::{ProviderError, ProviderResult};

#[derive(Debug, Clone, Default)]
pub struct AppleIapClient;

impl AppleIapClient {
    pub fn verify_receipt(&self, receipt: &str) -> ProviderResult<bool> {
        if receipt.trim().is_empty() {
            return Err(ProviderError::Rejected(
                "apple receipt is required".to_string(),
            ));
        }
        Ok(true)
    }
}
