use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use tokio::sync::mpsc;

pub const MAX_AGENT_SESSIONS: u8 = 3;

/// Whether this connection belongs to a support agent or an end user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnRole {
    /// End user (aud: public or platform).
    User,
    /// Support agent (aud: control).
    Agent,
}

/// A live WebSocket connection registered in the chat service.
pub struct ConnHandle {
    pub user_id: String,
    pub user_name: Option<String>,
    pub role: ConnRole,
    /// For users: the session_id they are currently in (waiting or active).
    pub session_id: Option<String>,
    /// For agents: number of currently active sessions they are handling (0–3).
    pub active_count: Arc<AtomicU8>,
    /// Channel to forward outbound messages to this connection's send task.
    pub tx: mpsc::UnboundedSender<axum::extract::ws::Message>,
}

impl ConnHandle {
    pub fn new_user(
        user_id: String,
        user_name: Option<String>,
        session_id: Option<String>,
        tx: mpsc::UnboundedSender<axum::extract::ws::Message>,
    ) -> Self {
        Self {
            user_id,
            user_name,
            role: ConnRole::User,
            session_id,
            active_count: Arc::new(AtomicU8::new(0)),
            tx,
        }
    }

    pub fn new_agent(
        user_id: String,
        user_name: Option<String>,
        tx: mpsc::UnboundedSender<axum::extract::ws::Message>,
    ) -> Self {
        Self {
            user_id,
            user_name,
            role: ConnRole::Agent,
            session_id: None,
            active_count: Arc::new(AtomicU8::new(0)),
            tx,
        }
    }

    /// Returns true if this agent can accept another session.
    pub fn has_capacity(&self) -> bool {
        self.role == ConnRole::Agent
            && self.active_count.load(Ordering::Relaxed) < MAX_AGENT_SESSIONS
    }

    pub fn increment_active(&self) {
        self.active_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_active(&self) {
        let current = self.active_count.load(Ordering::Relaxed);
        if current > 0 {
            self.active_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Send a server message to this connection. Errors are silently dropped
    /// (the connection has already gone away).
    pub fn send(&self, msg: &crate::messages::ServerMsg) {
        let _ = self.tx.send(msg.to_ws_text());
    }
}

pub struct AppState {
    /// Keyed by user_id — at most one active WebSocket per user at a time.
    pub connections: DashMap<String, ConnHandle>,
    pub db: sqlx::PgPool,
    pub nats: async_nats::Client,
    /// Minutes before a waiting session without an agent auto-converts to a ticket.
    pub queue_timeout_mins: u64,
}

impl AppState {
    pub fn new(db: sqlx::PgPool, nats: async_nats::Client, queue_timeout_mins: u64) -> Self {
        Self {
            connections: DashMap::new(),
            db,
            nats,
            queue_timeout_mins,
        }
    }

    /// Broadcast a message to all connected agents.
    pub fn broadcast_agents(&self, msg: &crate::messages::ServerMsg) {
        for entry in self.connections.iter() {
            if entry.value().role == ConnRole::Agent {
                entry.value().send(msg);
            }
        }
    }

    /// Send a message to a specific user by user_id.
    pub fn send_to(&self, user_id: &str, msg: &crate::messages::ServerMsg) {
        if let Some(handle) = self.connections.get(user_id) {
            handle.send(msg);
        }
    }
}
