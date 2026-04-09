use serde::{Deserialize, Serialize};

/// Messages sent from a client (user or agent) to the server.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Send a chat message within a session.
    SendMessage { session_id: String, content: String },
    /// Typing indicator — let the other party know the sender is typing.
    Typing { session_id: String },
    /// Agent claims a waiting session from the queue.
    ClaimSession { session_id: String },
    /// Either party closes the session.
    CloseSession { session_id: String },
}

/// Messages sent from the server to a client.
#[derive(Debug, Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// A chat message was received.
    Message {
        session_id: String,
        msg_id: String,
        sender_id: String,
        sender_type: String,
        content: String,
        sent_at: i64,
    },
    /// The other party is typing.
    Typing {
        session_id: String,
        sender_id: String,
    },
    /// User's current position in the waiting queue.
    QueuePos {
        session_id: String,
        position: i32,
    },
    /// An agent has claimed this session.
    Assigned {
        session_id: String,
        agent_id: String,
        agent_name: String,
    },
    /// Session has been closed. ticket_id is set if auto-saved as a support ticket.
    Closed {
        session_id: String,
        ticket_id: Option<String>,
    },
    /// Sent to agents: current state of the waiting queue.
    QueueUpdate { sessions: Vec<QueueEntry> },
    /// An error occurred processing a client message.
    Error { message: String },
}

/// A waiting session entry shown in the agent queue.
#[derive(Debug, Serialize, Clone)]
pub struct QueueEntry {
    pub session_id: String,
    pub user_id: String,
    pub user_name: Option<String>,
    pub queue_position: i32,
    pub created_at: i64,
}

impl ServerMsg {
    pub fn to_ws_text(&self) -> axum::extract::ws::Message {
        let json = serde_json::to_string(self).unwrap_or_default();
        axum::extract::ws::Message::Text(json.into())
    }
}
