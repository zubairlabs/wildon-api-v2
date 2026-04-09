pub fn render_export_csv(user_id: &str, export_kind: &str, generated_at: i64) -> String {
    format!("user_id,export_kind,generated_at\n{user_id},{export_kind},{generated_at}\n")
}
