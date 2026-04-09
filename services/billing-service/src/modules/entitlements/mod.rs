use std::collections::{HashMap, HashSet};

pub fn default_plan_entitlements() -> HashMap<String, HashSet<String>> {
    let mut plans = HashMap::new();

    plans.insert(
        "free".to_string(),
        HashSet::from(["profile_read".to_string()]),
    );
    plans.insert(
        "pro".to_string(),
        HashSet::from([
            "profile_read".to_string(),
            "profile_write".to_string(),
            "device_manage".to_string(),
        ]),
    );

    plans
}

pub fn is_feature_allowed(
    plan: &str,
    feature_key: &str,
    plan_entitlements: &HashMap<String, HashSet<String>>,
) -> bool {
    plan_entitlements
        .get(plan)
        .map(|set| set.contains(feature_key))
        .unwrap_or(false)
}
