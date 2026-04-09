use crate::{AiCompletion, ProviderError, ProviderResult};

#[derive(Debug, Clone)]
pub struct OpenAiClient {
    api_key: Option<String>,
    model: String,
}

impl OpenAiClient {
    pub fn from_env() -> Self {
        Self {
            api_key: std::env::var("OPENAI_API_KEY").ok(),
            model: std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string()),
        }
    }

    pub fn complete(&self, prompt: &str, max_tokens: u32) -> ProviderResult<AiCompletion> {
        if self.api_key.is_none() {
            return Err(ProviderError::Misconfigured("OPENAI_API_KEY"));
        }
        if prompt.trim().is_empty() {
            return Err(ProviderError::Rejected("prompt is required".to_string()));
        }

        let safe_max_tokens = max_tokens.clamp(16, 1024);
        let prompt_tokens = std::cmp::max((prompt.len() / 4) as u32, 1);
        let completion_tokens = std::cmp::min(safe_max_tokens, 128);
        let text = format!(
            "Model {} response: {}",
            self.model,
            prompt.chars().take(80).collect::<String>()
        );
        let cost_micros = (prompt_tokens as u64 * 120) + (completion_tokens as u64 * 480);

        Ok(AiCompletion {
            text,
            prompt_tokens,
            completion_tokens,
            cost_micros,
            model: self.model.clone(),
        })
    }
}

impl Default for OpenAiClient {
    fn default() -> Self {
        Self::from_env()
    }
}
