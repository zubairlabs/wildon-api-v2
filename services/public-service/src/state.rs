use crate::modules::{devices::DeviceData, users::UserProfileData};
use contracts::wildon::{
    billing::v1::billing_service_client::BillingServiceClient,
    logs::v1::logs_service_client::LogsServiceClient,
    users::v1::users_service_client::UsersServiceClient,
};
use event_bus::InMemoryOutbox;
use export_sdk::ExportSdkClient;
use std::{collections::HashMap, sync::Arc};
use storage_sdk::StorageSdkClient;
use tokio::sync::Mutex;
use tonic::transport::Channel;

#[derive(Debug, Default)]
pub struct PublicData {
    pub profiles: HashMap<String, UserProfileData>,
    pub devices: HashMap<String, Vec<DeviceData>>,
    pub outbox: InMemoryOutbox,
}

#[derive(Clone)]
pub struct AppState {
    pub data: Arc<Mutex<PublicData>>,
    pub billing_client: Arc<Mutex<BillingServiceClient<Channel>>>,
    pub logs_client: Arc<Mutex<LogsServiceClient<Channel>>>,
    pub users_client: Arc<Mutex<UsersServiceClient<Channel>>>,
    pub storage_client: Arc<Mutex<StorageSdkClient>>,
    pub export_client: Arc<Mutex<ExportSdkClient>>,
}

impl AppState {
    pub fn new(
        billing_client: BillingServiceClient<Channel>,
        logs_client: LogsServiceClient<Channel>,
        users_client: UsersServiceClient<Channel>,
        storage_client: StorageSdkClient,
        export_client: ExportSdkClient,
    ) -> Self {
        Self {
            data: Arc::new(Mutex::new(PublicData::default())),
            billing_client: Arc::new(Mutex::new(billing_client)),
            logs_client: Arc::new(Mutex::new(logs_client)),
            users_client: Arc::new(Mutex::new(users_client)),
            storage_client: Arc::new(Mutex::new(storage_client)),
            export_client: Arc::new(Mutex::new(export_client)),
        }
    }
}
