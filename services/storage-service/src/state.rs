use contracts::wildon::storage::v1::{ObjectMetadata, ObjectStatus};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub default_url_ttl_seconds: i64,
    pub profile_photo_max_bytes: u64,
    pub profile_photo_signed_url_ttl_seconds: i64,
}

impl StorageConfig {
    pub fn from_env() -> Self {
        let endpoint =
            std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "https://s3.wasabisys.com".to_string());
        let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "wildon-dev".to_string());
        let default_url_ttl_seconds = std::env::var("STORAGE_SIGNED_URL_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(900);
        let profile_photo_max_bytes = std::env::var("STORAGE_PROFILE_PHOTO_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(5 * 1024 * 1024);
        let profile_photo_signed_url_ttl_seconds =
            std::env::var("STORAGE_PROFILE_PHOTO_SIGNED_URL_TTL_SECONDS")
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(300);

        Self {
            endpoint,
            region,
            bucket,
            default_url_ttl_seconds,
            profile_photo_max_bytes,
            profile_photo_signed_url_ttl_seconds,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredObject {
    pub object_key: String,
    pub content_type: String,
    pub content_length: u64,
    pub tags: HashMap<String, String>,
    pub checksum: String,
    pub status: ObjectStatus,
    pub created_at: i64,
    pub updated_at: i64,
}

impl StoredObject {
    pub fn to_proto(&self) -> ObjectMetadata {
        ObjectMetadata {
            object_key: self.object_key.clone(),
            content_type: self.content_type.clone(),
            content_length: self.content_length,
            tags: self.tags.clone(),
            checksum: self.checksum.clone(),
            status: self.status as i32,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: StorageConfig,
    pub objects: Arc<Mutex<HashMap<String, StoredObject>>>,
}

impl AppState {
    pub fn new(config: StorageConfig) -> Self {
        Self {
            config,
            objects: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
