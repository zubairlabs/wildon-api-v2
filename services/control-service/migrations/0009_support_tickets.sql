CREATE TABLE IF NOT EXISTS control_app.support_tickets (
    ticket_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    user_name TEXT,
    user_email TEXT,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'responded', 'closed')),
    priority TEXT CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    category TEXT,
    assigned_to TEXT,
    assigned_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS support_tickets_status_updated_idx
    ON control_app.support_tickets (status, updated_at DESC);

CREATE INDEX IF NOT EXISTS support_tickets_user_idx
    ON control_app.support_tickets (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS control_app.support_ticket_replies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id TEXT NOT NULL REFERENCES control_app.support_tickets(ticket_id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS support_ticket_replies_ticket_idx
    ON control_app.support_ticket_replies (ticket_id, created_at ASC);

CREATE TABLE IF NOT EXISTS control_app.support_ticket_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id TEXT NOT NULL REFERENCES control_app.support_tickets(ticket_id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    uploaded_by TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    url TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS support_ticket_attachments_ticket_idx
    ON control_app.support_ticket_attachments (ticket_id, uploaded_at ASC);
