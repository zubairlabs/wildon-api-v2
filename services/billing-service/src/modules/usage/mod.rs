use crate::state::UsageKey;
use std::collections::HashMap;

pub fn record_usage(
    totals: &mut HashMap<UsageKey, u64>,
    user_id: &str,
    metric: &str,
    amount: u64,
) -> u64 {
    let key = (user_id.to_string(), metric.to_string());
    let entry = totals.entry(key).or_insert(0);
    *entry += amount;
    *entry
}
