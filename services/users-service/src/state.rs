use crate::modules::users::UserRecordData;
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
use storage_sdk::StorageSdkClient;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub users: Arc<Mutex<HashMap<String, UserRecordData>>>,
    pub db: PgPool,
    pub storage_client: Arc<Mutex<StorageSdkClient>>,
}

impl AppState {
    pub fn new(db: PgPool, storage_client: StorageSdkClient) -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            db,
            storage_client: Arc::new(Mutex::new(storage_client)),
        }
    }
}
