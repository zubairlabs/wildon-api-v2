use provider_clients::{openai::OpenAiClient, AiCompletion, ProviderError};

pub fn generate_text(
    client: &OpenAiClient,
    prompt: &str,
    max_tokens: u32,
) -> Result<AiCompletion, ProviderError> {
    client.complete(prompt, max_tokens)
}
