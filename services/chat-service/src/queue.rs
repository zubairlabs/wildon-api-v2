use chrono::Utc;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    events,
    messages::{QueueEntry, ServerMsg},
    state::AppState,
};

/// Fetch all waiting sessions ordered by queue position as `QueueEntry` items.
pub async fn get_waiting_queue(db: &PgPool) -> Vec<QueueEntry> {
    let rows = sqlx::query(
        r#"
        SELECT session_id, user_id, user_name, queue_position, created_at
        FROM control_app.live_chat_sessions
        WHERE status = 'waiting'
        ORDER BY queue_position ASC NULLS LAST, created_at ASC
        "#,
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    rows.into_iter()
        .map(|r| QueueEntry {
            session_id: r.get("session_id"),
            user_id: r.get("user_id"),
            user_name: r.get("user_name"),
            queue_position: r.get::<Option<i32>, _>("queue_position").unwrap_or(99),
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").timestamp(),
        })
        .collect()
}

/// Create a new waiting session for a user and return (session_id, queue_position).
pub async fn join_queue(
    db: &PgPool,
    user_id: &str,
    user_name: Option<&str>,
    user_email: Option<&str>,
) -> Result<(String, i32), String> {
    // Assign queue position = current max + 1
    let position_row = sqlx::query(
        "SELECT COALESCE(MAX(queue_position), 0)::int AS max_pos FROM control_app.live_chat_sessions WHERE status = 'waiting'",
    )
    .fetch_one(db)
    .await
    .map_err(|e| format!("db error getting queue position: {e}"))?;

    let queue_position: i32 = position_row.get::<Option<i32>, _>("max_pos").unwrap_or(0) + 1;

    let row = sqlx::query(
        r#"
        INSERT INTO control_app.live_chat_sessions
            (user_id, user_name, user_email, status, queue_position)
        VALUES ($1, $2, $3, 'waiting', $4)
        RETURNING session_id
        "#,
    )
    .bind(user_id)
    .bind(user_name)
    .bind(user_email)
    .bind(queue_position)
    .fetch_one(db)
    .await
    .map_err(|e| format!("db error creating session: {e}"))?;

    Ok((row.get("session_id"), queue_position))
}

/// Resume an existing waiting session for a user (reconnect case).
/// Returns (session_id, queue_position) if found.
pub async fn find_waiting_session(
    db: &PgPool,
    user_id: &str,
) -> Option<(String, i32)> {
    let row = sqlx::query(
        r#"
        SELECT session_id, queue_position
        FROM control_app.live_chat_sessions
        WHERE user_id = $1 AND status IN ('waiting', 'active')
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .ok()??;

    Some((row.get("session_id"), row.get::<Option<i32>, _>("queue_position").unwrap_or(1)))
}

/// Agent claims a waiting session. Returns the user_id of the session owner on success.
pub async fn claim_session(
    state: &Arc<AppState>,
    session_id: &str,
    agent_id: &str,
    agent_name: &str,
) -> Result<String, String> {
    let updated = sqlx::query(
        r#"
        UPDATE control_app.live_chat_sessions
        SET status = 'active', agent_id = $1, agent_name = $2, started_at = NOW(), queue_position = NULL
        WHERE session_id = $3 AND status = 'waiting'
        RETURNING user_id
        "#,
    )
    .bind(agent_id)
    .bind(agent_name)
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("db error claiming session: {e}"))?
    .ok_or_else(|| "session not found or already claimed".to_string())?;

    // Reorder remaining queue positions
    reorder_queue(&state.db).await;

    Ok(updated.get("user_id"))
}

/// Reorder queue_position values for all waiting sessions (1, 2, 3, …).
pub async fn reorder_queue(db: &PgPool) {
    let _ = sqlx::query(
        r#"
        UPDATE control_app.live_chat_sessions s
        SET queue_position = ranked.new_pos
        FROM (
            SELECT session_id,
                   ROW_NUMBER() OVER (ORDER BY created_at ASC) AS new_pos
            FROM control_app.live_chat_sessions
            WHERE status = 'waiting'
        ) ranked
        WHERE s.session_id = ranked.session_id
        "#,
    )
    .execute(db)
    .await;
}

/// Close a session, auto-save as a support ticket, and notify both parties.
/// Returns the new ticket_id.
pub async fn close_session(
    state: &Arc<AppState>,
    session_id: &str,
) -> Result<Option<String>, String> {
    // Mark session closed
    let session = sqlx::query(
        r#"
        UPDATE control_app.live_chat_sessions
        SET status = 'closed', ended_at = NOW()
        WHERE session_id = $1 AND status IN ('waiting', 'active')
        RETURNING user_id, user_name, user_email, agent_id, agent_name
        "#,
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("db error closing session: {e}"))?
    .ok_or_else(|| "session not found or already closed".to_string())?;

    let user_id: String = session.get("user_id");
    let user_name: Option<String> = session.get("user_name");
    let user_email: Option<String> = session.get("user_email");
    let agent_id: Option<String> = session.get("agent_id");
    let agent_name: Option<String> = session.get("agent_name");

    // Auto-save as support ticket
    let ticket_id = auto_save_ticket(
        state,
        session_id,
        &user_id,
        user_name.as_deref(),
        user_email.as_deref(),
        agent_id.as_deref(),
        agent_name.as_deref(),
    )
    .await;

    // Notify both parties
    let closed_msg = ServerMsg::Closed {
        session_id: session_id.to_string(),
        ticket_id: ticket_id.clone(),
    };
    state.send_to(&user_id, &closed_msg);
    if let Some(ref aid) = agent_id {
        if let Some(handle) = state.connections.get(aid) {
            handle.decrement_active();
        }
        state.send_to(aid, &closed_msg);
    }

    // Broadcast updated queue to agents
    let queue = get_waiting_queue(&state.db).await;
    state.broadcast_agents(&ServerMsg::QueueUpdate { sessions: queue });

    // Publish NATS event for other replicas
    events::publish(
        &state.nats,
        events::SUBJECT_SESSION_CLOSED,
        &events::SessionClosedEvent {
            session_id: session_id.to_string(),
            ticket_id: ticket_id.clone(),
            user_id,
            agent_id,
        },
    )
    .await;

    Ok(ticket_id)
}

/// Create a support ticket from the session's chat history.
async fn auto_save_ticket(
    state: &Arc<AppState>,
    session_id: &str,
    user_id: &str,
    user_name: Option<&str>,
    user_email: Option<&str>,
    agent_id: Option<&str>,
    agent_name: Option<&str>,
) -> Option<String> {
    // Fetch all messages
    let messages = sqlx::query(
        "SELECT sender_id, sender_type, content, sent_at FROM control_app.live_chat_messages WHERE session_id = $1 ORDER BY sent_at ASC",
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await
    .ok()?;

    if messages.is_empty() {
        return None;
    }

    // First user message becomes the ticket body
    let first_msg = messages
        .iter()
        .find(|m| m.get::<String, _>("sender_type") == "user")
        .map(|m| m.get::<String, _>("content"))
        .unwrap_or_else(|| "(no messages)".to_string());

    let subject = format!(
        "Live Chat — {}",
        Utc::now().format("%Y-%m-%d %H:%M UTC")
    );

    // Generate ticket_id matching existing convention: TKT-{12 chars}
    let ticket_id = format!("TKT-{}", &Uuid::new_v4().to_string().replace('-', "")[..12]);

    let result = sqlx::query(
        r#"
        INSERT INTO control_app.support_tickets
            (ticket_id, user_id, user_name, user_email, subject, message, status, priority, category, assigned_to, assigned_name)
        VALUES ($1, $2, $3, $4, $5, $6, 'closed', 'normal', 'live_chat', $7, $8)
        "#,
    )
    .bind(&ticket_id)
    .bind(user_id)
    .bind(user_name)
    .bind(user_email)
    .bind(&subject)
    .bind(&first_msg)
    .bind(agent_id)
    .bind(agent_name)
    .execute(&state.db)
    .await;

    if let Err(err) = result {
        tracing::error!(session_id, error = %err, "failed to create support ticket from live chat");
        return None;
    }

    // Insert all messages as replies (skip the first user message which is already the ticket body)
    for msg in messages.iter().skip(1) {
        let sender_type: String = msg.get("sender_type");
        let sender_id: String = msg.get("sender_id");
        let content: String = msg.get("content");
        let sent_at: chrono::DateTime<chrono::Utc> = msg.get("sent_at");
        let author = if sender_type == "agent" {
            agent_id.unwrap_or(&sender_id).to_string()
        } else {
            sender_id
        };
        let _ = sqlx::query(
            "INSERT INTO control_app.support_ticket_replies (ticket_id, author, message, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(&ticket_id)
        .bind(&author)
        .bind(&content)
        .bind(sent_at)
        .execute(&state.db)
        .await;
    }

    // Link ticket_id back to the session
    let _ = sqlx::query(
        "UPDATE control_app.live_chat_sessions SET ticket_id = $1 WHERE session_id = $2",
    )
    .bind(&ticket_id)
    .bind(session_id)
    .execute(&state.db)
    .await;

    tracing::info!(session_id, ticket_id, "auto-saved live chat session as support ticket");
    Some(ticket_id)
}

/// Background task: auto-convert long-waiting sessions to tickets.
pub async fn run_queue_timeout_task(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let timeout_mins = state.queue_timeout_mins as i64;

        let timed_out = sqlx::query(
            r#"
            SELECT session_id
            FROM control_app.live_chat_sessions
            WHERE status = 'waiting'
              AND created_at < NOW() - ($1 || ' minutes')::interval
            "#,
        )
        .bind(timeout_mins.to_string())
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        for row in timed_out {
            let session_id: String = row.get("session_id");
            tracing::info!(session_id = %session_id, "queue timeout: auto-closing waiting session");

            // Insert a system message
            let _ = sqlx::query(
                "INSERT INTO control_app.live_chat_messages (session_id, sender_id, sender_type, content) VALUES ($1, 'system', 'system', 'No agents were available. Your conversation has been saved as a support ticket.')",
            )
            .bind(&session_id)
            .execute(&state.db)
            .await;

            if let Err(err) = close_session(&state, &session_id).await {
                tracing::warn!(session_id = %session_id, error = %err, "failed to auto-close timed-out session");
            }
        }
    }
}
