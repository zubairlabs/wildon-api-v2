CREATE TABLE IF NOT EXISTS control_app.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_ref TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('CLINIC', 'CARE_HOME', 'AGENCY', 'HOSPITAL', 'PHARMACY', 'OTHER')),
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    address TEXT NOT NULL,
    city TEXT NOT NULL,
    state TEXT NOT NULL,
    website TEXT,
    account_number TEXT,
    guardian_account_id TEXT,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'ARCHIVED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS organizations_name_idx
    ON control_app.organizations (name);

CREATE INDEX IF NOT EXISTS organizations_city_idx
    ON control_app.organizations (city);

CREATE TABLE IF NOT EXISTS control_app.professionals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_ref TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('DOCTOR', 'NURSE', 'CAREGIVER', 'THERAPIST', 'PHARMACIST', 'STAFF', 'OTHER')),
    specialty TEXT,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    address TEXT,
    license_number TEXT,
    account_number TEXT,
    guardian_account_id TEXT,
    organization_id UUID REFERENCES control_app.organizations(id) ON DELETE SET NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'ARCHIVED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS professionals_name_idx
    ON control_app.professionals (name);

CREATE INDEX IF NOT EXISTS professionals_org_idx
    ON control_app.professionals (organization_id);
