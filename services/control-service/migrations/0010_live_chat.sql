-- Live chat sessions: real-time queue-based support conversations
CREATE TABLE control_app.live_chat_sessions (
    session_id     TEXT        PRIMARY KEY DEFAULT 'CHAT-' || LEFT(gen_random_uuid()::text, 12),
    user_id        TEXT        NOT NULL,
    user_name      TEXT,
    user_email     TEXT,
    status         TEXT        NOT NULL DEFAULT 'waiting'
                               CHECK (status IN ('waiting', 'active', 'closed')),
    queue_position INTEGER,
    agent_id       TEXT,
    agent_name     TEXT,
    ticket_id      TEXT        REFERENCES control_app.support_tickets(ticket_id) ON DELETE SET NULL,
    started_at     TIMESTAMPTZ,  -- when agent claimed
    ended_at       TIMESTAMPTZ,  -- when closed
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Messages within a live chat session
CREATE TABLE control_app.live_chat_messages (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  TEXT        NOT NULL REFERENCES control_app.live_chat_sessions(session_id) ON DELETE CASCADE,
    sender_id   TEXT        NOT NULL,
    sender_type TEXT        NOT NULL CHECK (sender_type IN ('user', 'agent', 'system')),
    content     TEXT        NOT NULL,
    sent_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX live_chat_sessions_status_idx  ON control_app.live_chat_sessions (status, created_at DESC);
CREATE INDEX live_chat_sessions_user_idx    ON control_app.live_chat_sessions (user_id, created_at DESC);
CREATE INDEX live_chat_messages_session_idx ON control_app.live_chat_messages (session_id, sent_at ASC);
