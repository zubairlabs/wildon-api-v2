CREATE TABLE IF NOT EXISTS control_app.incident_states (
    alarm_id TEXT PRIMARY KEY,
    assigned_to TEXT,
    assigned_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    resolved_by TEXT,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS control_app.incident_timeline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alarm_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT,
    actor_type TEXT NOT NULL DEFAULT 'USER',
    description TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_alarm_time
    ON control_app.incident_timeline (alarm_id, created_at DESC);
