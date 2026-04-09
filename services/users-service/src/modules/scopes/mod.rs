pub fn normalize_scopes(scopes: Vec<String>) -> Vec<String> {
    let mut normalized: Vec<String> = scopes
        .into_iter()
        .map(|scope| scope.trim().to_lowercase())
        .filter(|scope| !scope.is_empty())
        .collect();
    normalized.sort();
    normalized.dedup();
    normalized
}
