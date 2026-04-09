#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSurface {
    Public,
    Platform,
    Control,
}

impl HostSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Platform => "platform",
            Self::Control => "control",
        }
    }

    pub fn expected_audience(self) -> &'static str {
        self.as_str()
    }

    pub fn expected_realm(self) -> &'static str {
        self.as_str()
    }
}

fn normalized_host(host_header: Option<&str>) -> &str {
    host_header
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
}

pub fn host_has_explicit_surface(host_header: Option<&str>) -> bool {
    let host = normalized_host(host_header);
    host.starts_with("desk.")
        || host.starts_with("partner.")
        || host.starts_with("platform.")
        || host.starts_with("control.")
        || host.starts_with("admin.")
}

pub fn surface_from_str(surface: &str) -> Option<HostSurface> {
    match surface.trim().to_ascii_lowercase().as_str() {
        "public" => Some(HostSurface::Public),
        "platform" => Some(HostSurface::Platform),
        "control" => Some(HostSurface::Control),
        _ => None,
    }
}

pub fn resolve_surface(host_header: Option<&str>, client_surface: Option<&str>) -> HostSurface {
    if host_has_explicit_surface(host_header) {
        return classify_host(host_header);
    }

    if let Some(surface) = client_surface.and_then(surface_from_str) {
        return surface;
    }

    classify_host(host_header)
}

pub fn classify_host(host_header: Option<&str>) -> HostSurface {
    let host = normalized_host(host_header);

    if host.starts_with("desk.") || host.starts_with("partner.") || host.starts_with("platform.") {
        HostSurface::Platform
    } else if host.starts_with("control.") || host.starts_with("admin.") {
        HostSurface::Control
    } else {
        HostSurface::Public
    }
}
