use provider_clients::{
    fcm::FcmClient, sendgrid::SendgridClient, twilio::TwilioClient, NotificationChannel,
    NotificationPayload, NotificationProvider,
};

#[derive(Debug, Clone)]
pub struct NotificationOutcome {
    pub delivered: bool,
    pub provider_used: String,
    pub attempted_providers: Vec<String>,
    pub failure_reason: String,
}

pub fn deliver_with_failover(
    channel: NotificationChannel,
    destination: &str,
    subject: &str,
    message: &str,
    sendgrid: &SendgridClient,
    twilio: &TwilioClient,
    fcm: &FcmClient,
) -> NotificationOutcome {
    let payload = NotificationPayload {
        destination: destination.to_string(),
        subject: subject.to_string(),
        message: message.to_string(),
    };

    let providers: Vec<&dyn NotificationProvider> = match channel {
        NotificationChannel::Email => vec![sendgrid, twilio, fcm],
        NotificationChannel::Sms => vec![twilio, sendgrid, fcm],
        NotificationChannel::Push => vec![fcm, sendgrid, twilio],
    };

    let mut attempted_providers = Vec::new();
    let mut failures = Vec::new();

    for provider in providers {
        let name = provider.provider_name().to_string();
        attempted_providers.push(name.clone());
        match provider.send(channel, &payload) {
            Ok(_) => {
                return NotificationOutcome {
                    delivered: true,
                    provider_used: name,
                    attempted_providers,
                    failure_reason: String::new(),
                };
            }
            Err(error) => failures.push(format!("{name}: {error}")),
        }
    }

    NotificationOutcome {
        delivered: false,
        provider_used: String::new(),
        attempted_providers,
        failure_reason: failures.join(" | "),
    }
}
