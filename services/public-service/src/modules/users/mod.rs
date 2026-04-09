use chrono::Utc;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct UserProfileData {
    pub user_id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub middle_name: String,
    pub preferred_name: String,
    pub display_name: String,
    pub timezone: String,
    pub updated_at: i64,
}

impl UserProfileData {
    pub fn full_name(&self) -> String {
        let mut parts = Vec::new();
        if !self.first_name.is_empty() {
            parts.push(self.first_name.as_str());
        }
        if !self.middle_name.is_empty() {
            parts.push(self.middle_name.as_str());
        }
        if !self.last_name.is_empty() {
            parts.push(self.last_name.as_str());
        }
        parts.join(" ")
    }
}

pub fn get_profile<'a>(
    profiles: &'a HashMap<String, UserProfileData>,
    user_id: &str,
) -> Option<&'a UserProfileData> {
    profiles.get(user_id)
}

pub fn update_profile(
    profiles: &mut HashMap<String, UserProfileData>,
    user_id: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    middle_name: Option<&str>,
    preferred_name: Option<&str>,
    display_name: Option<&str>,
    timezone: Option<&str>,
) -> Option<UserProfileData> {
    let profile = profiles.get_mut(user_id)?;
    if let Some(v) = first_name {
        profile.first_name = v.to_string();
    }
    if let Some(v) = last_name {
        profile.last_name = v.to_string();
    }
    if let Some(v) = middle_name {
        profile.middle_name = v.to_string();
    }
    if let Some(v) = preferred_name {
        profile.preferred_name = v.to_string();
    }
    if let Some(v) = display_name {
        profile.display_name = v.to_string();
    }
    if let Some(v) = timezone {
        profile.timezone = v.to_string();
    }
    profile.updated_at = Utc::now().timestamp();
    Some(profile.clone())
}
