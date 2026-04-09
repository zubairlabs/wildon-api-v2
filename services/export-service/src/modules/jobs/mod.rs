use contracts::wildon::export::v1::ExportJobStatus;

pub fn parse_export_format(input: &str) -> Result<String, &'static str> {
    let normalized = input.trim().to_lowercase();
    if normalized.is_empty() {
        return Ok("csv".to_string());
    }

    if normalized == "csv" {
        Ok(normalized)
    } else {
        Err("only csv export format is supported in phase 3")
    }
}

pub fn status_label(status: ExportJobStatus) -> &'static str {
    match status {
        ExportJobStatus::Queued => "queued",
        ExportJobStatus::Running => "running",
        ExportJobStatus::Completed => "completed",
        ExportJobStatus::Failed => "failed",
        ExportJobStatus::Unspecified => "unspecified",
    }
}
