use crate::state::StorageConfig;
use uuid::Uuid;

pub fn build_signed_url(
    config: &StorageConfig,
    method: &str,
    object_key: &str,
    expires_at: i64,
) -> String {
    let endpoint = config.endpoint.trim_end_matches('/');
    let token = Uuid::new_v4();
    format!(
        "{endpoint}/{bucket}/{key}?x-wildon-signature={token}&x-wildon-method={method}&x-wildon-expires={expires_at}&x-wildon-region={region}",
        bucket = config.bucket,
        key = object_key,
        region = config.region,
    )
}
