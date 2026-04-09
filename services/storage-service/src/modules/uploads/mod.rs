use uuid::Uuid;

pub fn build_object_key(owner_id: &str, filename: &str) -> String {
    let owner = sanitize_segment(owner_id);
    let file = sanitize_segment(filename);
    format!("{owner}/{}/{}", Uuid::new_v4().simple(), file)
}

pub fn build_profile_photo_object_key(owner_id: &str, extension: &str) -> String {
    let owner = sanitize_segment(owner_id);
    let ext = sanitize_extension(extension);
    format!("users/{owner}/profile/{}.{}", Uuid::new_v4().simple(), ext)
}

fn sanitize_segment(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => ch,
            _ => '_',
        })
        .collect();

    if sanitized.is_empty() {
        "object".to_string()
    } else {
        sanitized
    }
}

fn sanitize_extension(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            _ => '_',
        })
        .collect();

    if sanitized.is_empty() {
        "bin".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_photo_key_is_user_scoped() {
        let owner = "9f83c2a1-1111-4444-8888-abcdefabcdef";
        let key = build_profile_photo_object_key(owner, "jpg");
        let prefix = format!("users/{owner}/profile/");
        assert!(key.starts_with(prefix.as_str()));
        assert!(key.ends_with(".jpg"));
    }
}
