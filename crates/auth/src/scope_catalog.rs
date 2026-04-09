#[derive(Debug, Clone, Copy)]
pub struct ScopeCatalogEntry {
    pub name: &'static str,
    pub description: &'static str,
    pub first_party_default: bool,
    pub third_party_required: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RoleScopeDefaults {
    pub role: &'static str,
    pub scopes: &'static [&'static str],
}

pub const ASSIGNABLE_CONTROL_SCOPES: &[&str] = &[
    "platform:support",
    "platform:partner",
    "control:admin",
    "control:audit:read",
    "control:apps:read",
    "control:apps:write",
    "control:users:add",
    "control:users:remove",
    "control:users:list",
    "control:roles:assign",
    "control:roles:list",
    "control:scopes:assign",
    "control:scopes:list",
    "control:billing:settings",
    "control:billing:read",
    "control:billing:refund",
    "control:clients:read",
    "control:clients:write",
    "control:clients:secrets:rotate",
    "control:clients:status",
    "control:clients:audit:read",
];

pub const MANAGER_ASSIGNABLE_CONTROL_SCOPES: &[&str] = &[
    "platform:support",
    "platform:partner",
];

pub const ADMIN_ASSIGNABLE_CONTROL_SCOPES: &[&str] = &[
    "platform:support",
    "platform:partner",
    "control:audit:read",
    "control:apps:read",
    "control:apps:write",
    "control:users:add",
    "control:users:remove",
    "control:users:list",
    "control:roles:list",
    "control:scopes:list",
    "control:billing:settings",
    "control:billing:read",
    "control:billing:refund",
    "control:clients:read",
    "control:clients:write",
    "control:clients:secrets:rotate",
    "control:clients:status",
    "control:clients:audit:read",
];

const OIDC_DEFAULT_SCOPES: &[&str] = &["openid", "profile", "offline_access"];
const PUBLIC_AUDIENCE_DEFAULT_SCOPES: &[&str] = &["public:read", "public:write"];
const PLATFORM_AUDIENCE_DEFAULT_SCOPES: &[&str] = &["platform:read", "platform:write"];
const CONTROL_AUDIENCE_DEFAULT_SCOPES: &[&str] =
    &["control:read", "control:write", "billing:admin"];

const USER_ROLE_DEFAULT_SCOPES: &[&str] = &[];
const SUPPORT_ROLE_DEFAULT_SCOPES: &[&str] = &["platform:support"];
const PARTNER_ROLE_DEFAULT_SCOPES: &[&str] = &["platform:partner"];
const MANAGER_ROLE_DEFAULT_SCOPES: &[&str] = &[
    "control:users:add",
    "control:users:list",
    "control:roles:list",
    "control:scopes:list",
    "control:apps:read",
    "control:billing:read",
];
const AUDITOR_ROLE_DEFAULT_SCOPES: &[&str] = &[
    "control:audit:read",
    "control:users:list",
    "control:roles:list",
    "control:scopes:list",
    "control:clients:read",
    "control:clients:audit:read",
];
const ADMIN_ROLE_DEFAULT_SCOPES: &[&str] = &[
    "control:admin",
    "control:apps:read",
    "control:apps:write",
    "control:users:add",
    "control:users:remove",
    "control:users:list",
    "control:roles:assign",
    "control:roles:list",
    "control:scopes:assign",
    "control:scopes:list",
    "control:billing:settings",
    "control:billing:read",
    "control:billing:refund",
    "control:clients:read",
    "control:clients:write",
    "control:clients:secrets:rotate",
    "control:clients:status",
    "control:clients:audit:read",
];

const ROLE_SCOPE_DEFAULTS: &[RoleScopeDefaults] = &[
    RoleScopeDefaults {
        role: "user",
        scopes: USER_ROLE_DEFAULT_SCOPES,
    },
    RoleScopeDefaults {
        role: "support",
        scopes: SUPPORT_ROLE_DEFAULT_SCOPES,
    },
    RoleScopeDefaults {
        role: "partner",
        scopes: PARTNER_ROLE_DEFAULT_SCOPES,
    },
    RoleScopeDefaults {
        role: "manager",
        scopes: MANAGER_ROLE_DEFAULT_SCOPES,
    },
    RoleScopeDefaults {
        role: "auditor",
        scopes: AUDITOR_ROLE_DEFAULT_SCOPES,
    },
    RoleScopeDefaults {
        role: "admin",
        scopes: ADMIN_ROLE_DEFAULT_SCOPES,
    },
    RoleScopeDefaults {
        role: "superadmin",
        scopes: ADMIN_ROLE_DEFAULT_SCOPES,
    },
];

const SCOPE_CATALOG: &[ScopeCatalogEntry] = &[
    ScopeCatalogEntry {
        name: "openid",
        description: "OpenID Connect authentication scope.",
        first_party_default: true,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "profile",
        description: "Read basic profile identity fields.",
        first_party_default: true,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "offline_access",
        description: "Issue refresh tokens for long-lived sessions.",
        first_party_default: true,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "public:read",
        description: "Read access to user-facing public resources.",
        first_party_default: false,
        third_party_required: true,
    },
    ScopeCatalogEntry {
        name: "public:write",
        description: "Write access to user-facing public resources.",
        first_party_default: false,
        third_party_required: true,
    },
    ScopeCatalogEntry {
        name: "platform:read",
        description: "Read access to platform surface resources.",
        first_party_default: false,
        third_party_required: true,
    },
    ScopeCatalogEntry {
        name: "platform:write",
        description: "Write access to platform surface resources.",
        first_party_default: false,
        third_party_required: true,
    },
    ScopeCatalogEntry {
        name: "platform:support",
        description: "Desk/support module operations.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "platform:partner",
        description: "Partner module operations.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:admin",
        description: "High-privilege control-service administration.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:audit:read",
        description: "Read audit logs and auditor-safe governance activity.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:apps:read",
        description: "Read the fixed app catalog and app operational details.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:apps:write",
        description: "Update fixed app metadata and release controls.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:users:add",
        description: "Create control-managed users.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:users:remove",
        description: "Disable or remove control-managed users.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:users:list",
        description: "List and inspect control-managed users.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:roles:assign",
        description: "Assign roles in control surface.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:roles:list",
        description: "View role assignments in control surface.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:scopes:assign",
        description: "Assign delegated control scopes.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:scopes:list",
        description: "View delegated control scopes.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:billing:settings",
        description: "Manage invoice settings used for billing documents.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:billing:read",
        description: "Read billing invoices, transactions, and ledger entries.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:billing:refund",
        description: "Issue billing refunds from control surface.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:clients:read",
        description: "List and inspect API client registry records.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:clients:write",
        description: "Create and update API client registry records.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:clients:secrets:rotate",
        description: "Rotate confidential API client secrets.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:clients:status",
        description: "Suspend, revoke, or activate API clients.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:clients:audit:read",
        description: "Read API client audit event history.",
        first_party_default: false,
        third_party_required: false,
    },
    ScopeCatalogEntry {
        name: "control:read",
        description: "Read access to admin/control surface resources.",
        first_party_default: false,
        third_party_required: true,
    },
    ScopeCatalogEntry {
        name: "control:write",
        description: "Write access to admin/control surface resources.",
        first_party_default: false,
        third_party_required: true,
    },
    ScopeCatalogEntry {
        name: "billing:admin",
        description: "High-privilege billing administration scope.",
        first_party_default: false,
        third_party_required: true,
    },
];

pub fn scopes() -> &'static [ScopeCatalogEntry] {
    SCOPE_CATALOG
}

pub fn role_scope_defaults() -> &'static [RoleScopeDefaults] {
    ROLE_SCOPE_DEFAULTS
}

pub fn oidc_default_scopes() -> &'static [&'static str] {
    OIDC_DEFAULT_SCOPES
}

pub fn audience_default_scopes(audience: &str) -> &'static [&'static str] {
    if audience.eq_ignore_ascii_case("public") {
        PUBLIC_AUDIENCE_DEFAULT_SCOPES
    } else if audience.eq_ignore_ascii_case("platform") {
        PLATFORM_AUDIENCE_DEFAULT_SCOPES
    } else if audience.eq_ignore_ascii_case("control") {
        CONTROL_AUDIENCE_DEFAULT_SCOPES
    } else {
        &[]
    }
}

pub fn role_default_scopes(role: &str) -> &'static [&'static str] {
    if role.eq_ignore_ascii_case("user") {
        USER_ROLE_DEFAULT_SCOPES
    } else if role.eq_ignore_ascii_case("support") {
        SUPPORT_ROLE_DEFAULT_SCOPES
    } else if role.eq_ignore_ascii_case("partner") {
        PARTNER_ROLE_DEFAULT_SCOPES
    } else if role.eq_ignore_ascii_case("manager") {
        MANAGER_ROLE_DEFAULT_SCOPES
    } else if role.eq_ignore_ascii_case("auditor") {
        AUDITOR_ROLE_DEFAULT_SCOPES
    } else if role.eq_ignore_ascii_case("admin") || role.eq_ignore_ascii_case("superadmin") {
        ADMIN_ROLE_DEFAULT_SCOPES
    } else {
        &[]
    }
}

pub fn is_supported_scope(scope: &str) -> bool {
    SCOPE_CATALOG
        .iter()
        .any(|candidate| candidate.name == scope)
}

pub fn is_assignable_control_scope(scope: &str) -> bool {
    ASSIGNABLE_CONTROL_SCOPES.contains(&scope)
}

pub fn is_admin_assignable_control_scope(scope: &str) -> bool {
    ADMIN_ASSIGNABLE_CONTROL_SCOPES.contains(&scope)
}
