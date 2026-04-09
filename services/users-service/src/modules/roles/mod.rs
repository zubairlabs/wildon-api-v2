pub fn normalize_roles(roles: Vec<String>) -> Vec<String> {
    let mut normalized: Vec<String> = roles
        .into_iter()
        .map(|role| role.trim().to_lowercase())
        .filter(|role| !role.is_empty())
        .collect();
    normalized.sort();
    normalized.dedup();
    normalized
}
