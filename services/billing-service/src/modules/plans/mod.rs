use std::collections::HashMap;

pub fn resolve_plan(user_id: &str, plan_overrides: &HashMap<String, String>) -> String {
    if let Some(plan) = plan_overrides.get(user_id) {
        return plan.clone();
    }

    if user_id.starts_with("pro-") {
        "pro".to_string()
    } else {
        "free".to_string()
    }
}
