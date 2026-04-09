use crate::modules::{jobs::JobRecordData, states::StatesHandle};
use contracts::wildon::billing::v1::billing_service_client::BillingServiceClient;
use export_sdk::ExportSdkClient;
use provider_clients::{
    fcm::FcmClient, openai::OpenAiClient, sendgrid::SendgridClient, twilio::TwilioClient,
};
use std::{collections::HashMap, sync::Arc};
use storage_sdk::StorageSdkClient;
use tokio::sync::Mutex;
use tonic::transport::Channel;

#[derive(Debug, Clone)]
pub struct FeatureFlagState {
    pub key: String,
    pub enabled: bool,
    pub updated_by: String,
    pub reason: String,
    pub updated_at: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub feature_flags: Arc<Mutex<HashMap<String, FeatureFlagState>>>,
    pub jobs: Arc<Mutex<HashMap<String, JobRecordData>>>,
    pub job_idempotency: Arc<Mutex<HashMap<String, String>>>,
    pub sendgrid: Arc<SendgridClient>,
    pub twilio: Arc<TwilioClient>,
    pub fcm: Arc<FcmClient>,
    pub openai: Arc<OpenAiClient>,
    pub storage_client: Arc<Mutex<StorageSdkClient>>,
    pub export_client: Arc<Mutex<ExportSdkClient>>,
    pub billing_client: Arc<Mutex<BillingServiceClient<Channel>>>,
    pub service_states: Arc<StatesHandle>,
}

impl AppState {
    pub fn new(
        storage_client: StorageSdkClient,
        export_client: ExportSdkClient,
        billing_client: BillingServiceClient<Channel>,
    ) -> Self {
        Self {
            feature_flags: Arc::new(Mutex::new(HashMap::new())),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            job_idempotency: Arc::new(Mutex::new(HashMap::new())),
            sendgrid: Arc::new(SendgridClient::from_env()),
            twilio: Arc::new(TwilioClient::from_env()),
            fcm: Arc::new(FcmClient::from_env()),
            openai: Arc::new(OpenAiClient::from_env()),
            storage_client: Arc::new(Mutex::new(storage_client)),
            export_client: Arc::new(Mutex::new(export_client)),
            billing_client: Arc::new(Mutex::new(billing_client)),
            service_states: Arc::new(StatesHandle::new()),
        }
    }
}
