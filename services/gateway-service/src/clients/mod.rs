use config::grpc::{connect_channel, GrpcConfigError};
use contracts::wildon::{
    api_clients::v1::api_clients_service_client::ApiClientsServiceClient,
    auth::v1::auth_service_client::AuthServiceClient,
    billing::v1::billing_service_client::BillingServiceClient,
    logs::v1::logs_service_client::LogsServiceClient,
    public::v1::public_service_client::PublicServiceClient,
    users::v1::users_service_client::UsersServiceClient,
};
use tonic::transport::Channel;

pub async fn bootstrap_auth_client(
    endpoint: &str,
) -> Result<AuthServiceClient<Channel>, GrpcConfigError> {
    let channel = connect_channel(endpoint, "auth-service").await?;
    Ok(AuthServiceClient::new(channel))
}

pub async fn bootstrap_public_client(
    endpoint: &str,
) -> Result<PublicServiceClient<Channel>, GrpcConfigError> {
    let channel = connect_channel(endpoint, "public-service").await?;
    Ok(PublicServiceClient::new(channel))
}

pub async fn bootstrap_api_clients_client(
    endpoint: &str,
) -> Result<ApiClientsServiceClient<Channel>, GrpcConfigError> {
    let channel = connect_channel(endpoint, "api-clients-service").await?;
    Ok(ApiClientsServiceClient::new(channel))
}

pub async fn bootstrap_users_client(
    endpoint: &str,
) -> Result<UsersServiceClient<Channel>, GrpcConfigError> {
    let channel = connect_channel(endpoint, "users-service").await?;
    Ok(UsersServiceClient::new(channel))
}

pub async fn bootstrap_billing_client(
    endpoint: &str,
) -> Result<BillingServiceClient<Channel>, GrpcConfigError> {
    let channel = connect_channel(endpoint, "billing-service").await?;
    Ok(BillingServiceClient::new(channel))
}

pub async fn bootstrap_logs_client(
    endpoint: &str,
) -> Result<LogsServiceClient<Channel>, GrpcConfigError> {
    let channel = connect_channel(endpoint, "logs-service").await?;
    Ok(LogsServiceClient::new(channel))
}
