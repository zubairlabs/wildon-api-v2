use std::collections::HashMap;

pub fn merge_tags(target: &mut HashMap<String, String>, updates: HashMap<String, String>) {
    for (key, value) in updates {
        target.insert(key, value);
    }
}
