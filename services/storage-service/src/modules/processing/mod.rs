pub fn normalized_content_type(content_type: &str) -> String {
    if content_type.trim().is_empty() {
        "application/octet-stream".to_string()
    } else {
        content_type.trim().to_ascii_lowercase()
    }
}

pub fn profile_photo_content_type_to_extension(
    content_type: &str,
) -> Option<(&'static str, &'static str)> {
    match normalized_content_type(content_type).as_str() {
        "image/jpeg" | "image/jpg" => Some(("image/jpeg", "jpg")),
        "image/png" => Some(("image/png", "png")),
        "image/webp" => Some(("image/webp", "webp")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_photo_content_type_whitelist_is_enforced() {
        assert_eq!(
            profile_photo_content_type_to_extension("image/jpeg"),
            Some(("image/jpeg", "jpg"))
        );
        assert_eq!(
            profile_photo_content_type_to_extension("image/png"),
            Some(("image/png", "png"))
        );
        assert_eq!(
            profile_photo_content_type_to_extension("image/webp"),
            Some(("image/webp", "webp"))
        );
        assert!(profile_photo_content_type_to_extension("application/pdf").is_none());
    }
}
