use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

// NATS subjects for cross-replica coordination
pub const SUBJECT_CHAT_MESSAGE: &str = "wildon.chat.message";
pub const SUBJECT_SESSION_CREATED: &str = "wildon.chat.session.created";
pub const SUBJECT_SESSION_ASSIGNED: &str = "wildon.chat.session.assigned";
pub const SUBJECT_SESSION_CLOSED: &str = "wildon.chat.session.closed";

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatMessageEvent {
    pub session_id: String,
    pub msg_id: String,
    pub sender_id: String,
    pub sender_type: String,
    pub content: String,
    pub sent_at: i64,
    /// user_id of the recipient (user or agent) on another replica.
    pub recipient_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionCreatedEvent {
    pub session_id: String,
    pub user_id: String,
    pub user_name: Option<String>,
    pub queue_position: i32,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionAssignedEvent {
    pub session_id: String,
    pub agent_id: String,
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClosedEvent {
    pub session_id: String,
    pub ticket_id: Option<String>,
    pub user_id: String,
    pub agent_id: Option<String>,
}

pub async fn publish(nats: &async_nats::Client, subject: &str, payload: impl Serialize) {
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(err) = nats.publish(subject.to_string(), bytes.into()).await {
                tracing::warn!(subject, error = %err, "failed to publish NATS event");
            }
        }
        Err(err) => {
            tracing::warn!(subject, error = %err, "failed to serialize NATS event");
        }
    }
}

/// Subscribe to NATS subjects and forward messages to local connections.
/// This enables cross-replica delivery when the sender is on a different instance.
pub async fn spawn_nats_subscriber(state: Arc<AppState>) {
    let subjects = [
        SUBJECT_CHAT_MESSAGE,
        SUBJECT_SESSION_CLOSED,
    ];

    for subject in subjects {
        let state = Arc::clone(&state);
        let subject_str = subject.to_string();
        let nats = state.nats.clone();

        tokio::spawn(async move {
            let subscriber = match nats.subscribe(subject_str.clone()).await {
                Ok(s) => s,
                Err(err) => {
                    tracing::error!(subject = %subject_str, error = %err, "failed to subscribe to NATS subject");
                    return;
                }
            };

            tracing::info!(subject = %subject_str, "subscribed to NATS subject");

            let mut subscriber = subscriber;
            use futures_util::StreamExt;
            while let Some(msg) = subscriber.next().await {
                let payload = std::str::from_utf8(&msg.payload).unwrap_or_default();

                if subject_str == SUBJECT_CHAT_MESSAGE {
                    if let Ok(event) = serde_json::from_str::<ChatMessageEvent>(payload) {
                        // Only forward if the recipient is connected to this replica
                        state.send_to(
                            &event.recipient_id,
                            &crate::messages::ServerMsg::Message {
                                session_id: event.session_id,
                                msg_id: event.msg_id,
                                sender_id: event.sender_id,
                                sender_type: event.sender_type,
                                content: event.content,
                                sent_at: event.sent_at,
                            },
                        );
                    }
                } else if subject_str == SUBJECT_SESSION_CLOSED {
                    if let Ok(event) = serde_json::from_str::<SessionClosedEvent>(payload) {
                        let closed_msg = crate::messages::ServerMsg::Closed {
                            session_id: event.session_id.clone(),
                            ticket_id: event.ticket_id.clone(),
                        };
                        state.send_to(&event.user_id, &closed_msg);
                        if let Some(ref agent_id) = event.agent_id {
                            state.send_to(agent_id, &closed_msg);
                        }
                    }
                }
            }

            tracing::warn!(subject = %subject_str, "NATS subscription closed");
        });
    }
}
