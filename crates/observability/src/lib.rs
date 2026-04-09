use tracing_subscriber::{fmt, EnvFilter};

pub fn init_tracing(service_name: &str) {
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .with_thread_names(true)
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_file(false)
        .with_line_number(false)
        .try_init();
    tracing::info!(service = service_name, "tracing initialized");
}
