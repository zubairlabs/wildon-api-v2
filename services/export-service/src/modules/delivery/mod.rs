pub fn artifact_key(user_id: &str, job_id: &str, format: &str) -> String {
    format!("exports/{user_id}/{job_id}.{format}")
}
