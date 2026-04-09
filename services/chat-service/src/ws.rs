use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

use auth::{
    claims::Claims,
    jwt::{decode_token, validate_claims},
};

use crate::{
    events,
    messages::{ClientMsg, ServerMsg},
    queue,
    state::{AppState, ConnHandle},
};

#[derive(serde::Deserialize)]
pub struct WsParams {
    token: Option<String>,
}

/// WebSocket upgrade handler.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let token = match params.token {
        Some(t) if !t.is_empty() => t,
        _ => return (StatusCode::UNAUTHORIZED, "missing token").into_response(),
    };

    let claims = match decode_token(&token) {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "ws: invalid JWT");
            return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
        }
    };

    if let Err(err) = validate_claims(&claims) {
        tracing::warn!(error = %err, sub = %claims.sub, "ws: claims validation failed");
        return (StatusCode::UNAUTHORIZED, "token rejected").into_response();
    }

    ws.on_upgrade(move |socket| handle_socket(state, socket, claims))
}

async fn handle_socket(state: Arc<AppState>, socket: WebSocket, claims: Claims) {
    let user_id = claims.sub.clone();
    let is_agent = claims.aud == "control";
    let user_name: Option<String> = None; // could resolve from DB; keep lightweight for now

    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Spawn task: forward outbound messages from channel → WebSocket sender
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    if is_agent {
        connect_agent(&state, &user_id, user_name, tx).await;
    } else {
        connect_user(&state, &user_id, user_name, tx).await;
    }

    // Process incoming messages
    while let Some(Ok(msg)) = ws_rx.next().await {
        match msg {
            Message::Text(text) => {
                handle_text(&state, &user_id, is_agent, &text).await;
            }
            Message::Close(_) => break,
            Message::Ping(data) => {
                if let Some(handle) = state.connections.get(&user_id) {
                    let _ = handle.tx.send(Message::Pong(data));
                }
            }
            _ => {}
        }
    }

    // Cleanup on disconnect
    on_disconnect(&state, &user_id, is_agent).await;
}

async fn connect_agent(
    state: &Arc<AppState>,
    user_id: &str,
    user_name: Option<String>,
    tx: mpsc::UnboundedSender<Message>,
) {
    state.connections.insert(
        user_id.to_string(),
        ConnHandle::new_agent(user_id.to_string(), user_name, tx),
    );

    // Send current queue to the newly connected agent
    let queue = queue::get_waiting_queue(&state.db).await;
    state.send_to(user_id, &ServerMsg::QueueUpdate { sessions: queue });

    tracing::info!(user_id, "agent connected");
}

async fn connect_user(
    state: &Arc<AppState>,
    user_id: &str,
    user_name: Option<String>,
    tx: mpsc::UnboundedSender<Message>,
) {
    // Check for an existing waiting/active session (reconnect case)
    let (session_id, position) = match queue::find_waiting_session(&state.db, user_id).await {
        Some((sid, pos)) => (sid, pos),
        None => {
            // Create a new waiting session
            match queue::join_queue(&state.db, user_id, user_name.as_deref(), None).await {
                Ok((sid, pos)) => (sid, pos),
                Err(err) => {
                    tracing::error!(user_id, error = %err, "failed to create chat session");
                    return;
                }
            }
        }
    };

    state.connections.insert(
        user_id.to_string(),
        ConnHandle::new_user(user_id.to_string(), user_name, Some(session_id.clone()), tx),
    );

    // Tell the user their queue position
    state.send_to(
        user_id,
        &ServerMsg::QueuePos {
            session_id: session_id.clone(),
            position,
        },
    );

    // Notify all agents of the updated queue
    let queue_entries = queue::get_waiting_queue(&state.db).await;
    state.broadcast_agents(&ServerMsg::QueueUpdate {
        sessions: queue_entries.clone(),
    });

    // Publish NATS event so other replicas know about the new session
    events::publish(
        &state.nats,
        events::SUBJECT_SESSION_CREATED,
        &events::SessionCreatedEvent {
            session_id,
            user_id: user_id.to_string(),
            user_name: None,
            queue_position: position,
            created_at: chrono::Utc::now().timestamp(),
        },
    )
    .await;

    tracing::info!(user_id, "user connected to chat queue");
}

async fn handle_text(state: &Arc<AppState>, user_id: &str, is_agent: bool, text: &str) {
    let msg = match serde_json::from_str::<ClientMsg>(text) {
        Ok(m) => m,
        Err(_) => {
            state.send_to(
                user_id,
                &ServerMsg::Error {
                    message: "invalid message format".to_string(),
                },
            );
            return;
        }
    };

    match msg {
        ClientMsg::SendMessage {
            session_id,
            content,
        } => {
            handle_send_message(state, user_id, is_agent, &session_id, content).await;
        }
        ClientMsg::Typing { session_id } => {
            handle_typing(state, user_id, is_agent, &session_id).await;
        }
        ClientMsg::ClaimSession { session_id } => {
            if is_agent {
                handle_claim_session(state, user_id, &session_id).await;
            }
        }
        ClientMsg::CloseSession { session_id } => {
            if let Err(err) = queue::close_session(state, &session_id).await {
                tracing::warn!(user_id, session_id, error = %err, "close session failed");
            }
        }
    }
}

async fn handle_send_message(
    state: &Arc<AppState>,
    sender_id: &str,
    is_agent: bool,
    session_id: &str,
    content: String,
) {
    let content = content.trim().to_string();
    if content.is_empty() {
        return;
    }

    // Verify sender is a participant in this session
    let session = sqlx::query(
        "SELECT user_id, agent_id, status FROM control_app.live_chat_sessions WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let session = match session {
        Some(s) if s.get::<String, _>("status") == "active" => s,
        _ => {
            state.send_to(
                sender_id,
                &ServerMsg::Error {
                    message: "session not active".to_string(),
                },
            );
            return;
        }
    };

    let session_user_id: String = session.get("user_id");
    let session_agent_id: Option<String> = session.get("agent_id");

    let is_participant = if is_agent {
        session_agent_id.as_deref() == Some(sender_id)
    } else {
        session_user_id == sender_id
    };

    if !is_participant {
        state.send_to(
            sender_id,
            &ServerMsg::Error {
                message: "not a participant in this session".to_string(),
            },
        );
        return;
    }

    let sender_type = if is_agent { "agent" } else { "user" };

    // Persist message
    let row = sqlx::query(
        r#"
        INSERT INTO control_app.live_chat_messages (session_id, sender_id, sender_type, content)
        VALUES ($1, $2, $3, $4)
        RETURNING id, sent_at
        "#,
    )
    .bind(session_id)
    .bind(sender_id)
    .bind(sender_type)
    .bind(&content)
    .fetch_one(&state.db)
    .await;

    let (msg_id, sent_at) = match row {
        Ok(r) => (
            r.get::<Uuid, _>("id").to_string(),
            r.get::<chrono::DateTime<chrono::Utc>, _>("sent_at").timestamp(),
        ),
        Err(err) => {
            tracing::error!(error = %err, "failed to persist chat message");
            state.send_to(
                sender_id,
                &ServerMsg::Error {
                    message: "failed to send message".to_string(),
                },
            );
            return;
        }
    };

    let outbound = ServerMsg::Message {
        session_id: session_id.to_string(),
        msg_id: msg_id.clone(),
        sender_id: sender_id.to_string(),
        sender_type: sender_type.to_string(),
        content: content.clone(),
        sent_at,
    };

    // Deliver to both participants locally
    state.send_to(&session_user_id, &outbound);
    if let Some(ref agent_id) = session_agent_id {
        state.send_to(agent_id, &outbound);

        // Publish to NATS for cross-replica delivery
        let recipient = if is_agent {
            session_user_id.clone()
        } else {
            agent_id.clone()
        };
        events::publish(
            &state.nats,
            events::SUBJECT_CHAT_MESSAGE,
            &events::ChatMessageEvent {
                session_id: session_id.to_string(),
                msg_id,
                sender_id: sender_id.to_string(),
                sender_type: sender_type.to_string(),
                content,
                sent_at,
                recipient_id: recipient,
            },
        )
        .await;
    }
}

async fn handle_typing(
    state: &Arc<AppState>,
    sender_id: &str,
    is_agent: bool,
    session_id: &str,
) {
    let session = sqlx::query(
        "SELECT user_id, agent_id FROM control_app.live_chat_sessions WHERE session_id = $1 AND status = 'active'",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    if let Some(session) = session {
        let user_id: String = session.get("user_id");
        let agent_id: Option<String> = session.get("agent_id");
        let typing_msg = ServerMsg::Typing {
            session_id: session_id.to_string(),
            sender_id: sender_id.to_string(),
        };
        // Send to the other party
        if is_agent {
            state.send_to(&user_id, &typing_msg);
        } else if let Some(ref aid) = agent_id {
            state.send_to(aid, &typing_msg);
        }
    }
}

async fn handle_claim_session(state: &Arc<AppState>, agent_id: &str, session_id: &str) {
    // Check agent capacity
    let has_capacity = state
        .connections
        .get(agent_id)
        .map(|h| h.has_capacity())
        .unwrap_or(false);

    if !has_capacity {
        state.send_to(
            agent_id,
            &ServerMsg::Error {
                message: format!("at capacity ({} active sessions)", crate::state::MAX_AGENT_SESSIONS),
            },
        );
        return;
    }

    // Resolve agent name
    let agent_name = state
        .connections
        .get(agent_id)
        .and_then(|h| h.user_name.clone())
        .unwrap_or_else(|| agent_id.to_string());

    match queue::claim_session(state, session_id, agent_id, &agent_name).await {
        Ok(user_id) => {
            // Increment agent's active session count
            if let Some(handle) = state.connections.get(agent_id) {
                handle.increment_active();
            }

            let assigned_msg = ServerMsg::Assigned {
                session_id: session_id.to_string(),
                agent_id: agent_id.to_string(),
                agent_name: agent_name.clone(),
            };

            // Notify user and agent
            state.send_to(&user_id, &assigned_msg);
            state.send_to(agent_id, &assigned_msg);

            // Broadcast updated queue to all agents
            let queue = queue::get_waiting_queue(&state.db).await;
            state.broadcast_agents(&ServerMsg::QueueUpdate { sessions: queue });

            // Publish NATS event
            events::publish(
                &state.nats,
                events::SUBJECT_SESSION_ASSIGNED,
                &events::SessionAssignedEvent {
                    session_id: session_id.to_string(),
                    agent_id: agent_id.to_string(),
                    user_id,
                },
            )
            .await;

            tracing::info!(agent_id, session_id, "agent claimed chat session");
        }
        Err(err) => {
            tracing::warn!(agent_id, session_id, error = %err, "failed to claim session");
            state.send_to(
                agent_id,
                &ServerMsg::Error {
                    message: format!("could not claim session: {err}"),
                },
            );
        }
    }
}

async fn on_disconnect(state: &Arc<AppState>, user_id: &str, is_agent: bool) {
    if is_agent {
        state.connections.remove(user_id);
        tracing::info!(user_id, "agent disconnected");
    } else {
        let session_id = state
            .connections
            .get(user_id)
            .and_then(|h| h.session_id.clone());

        state.connections.remove(user_id);

        // If the user had a waiting session and disconnected, close it
        if let Some(ref sid) = session_id {
            let status = sqlx::query(
                "SELECT status FROM control_app.live_chat_sessions WHERE session_id = $1",
            )
            .bind(sid.as_str())
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|r| r.get::<String, _>("status"));

            if matches!(status.as_deref(), Some("waiting") | Some("active")) {
                if let Err(err) = queue::close_session(state, sid).await {
                    tracing::warn!(user_id, session_id = sid, error = %err, "error closing session on disconnect");
                }
            }
        }

        tracing::info!(user_id, "user disconnected from chat");
    }
}
