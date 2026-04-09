use std::collections::{BTreeSet, HashMap};

const MAX_SUBJECT_LEN: usize = 200;
const MAX_HTML_LEN: usize = 50_000;
const MAX_VARIABLES: usize = 64;
const MAX_VARIABLE_VALUE_LEN: usize = 4_096;

pub const EMAIL_TEMPLATE_NAME_EMAIL_OTP: &str = "email-otp";
pub const EMAIL_TEMPLATE_NAME_WELCOME: &str = "welcome";
pub const EMAIL_TEMPLATE_NAME_PASSWORD_RESET_REQUEST: &str = "password-reset-request";
pub const EMAIL_TEMPLATE_NAME_PASSWORD_CHANGED_SUCCESS: &str = "password-changed-success";
pub const SUPPORTED_EMAIL_TEMPLATE_NAMES: [&str; 4] = [
    EMAIL_TEMPLATE_NAME_EMAIL_OTP,
    EMAIL_TEMPLATE_NAME_WELCOME,
    EMAIL_TEMPLATE_NAME_PASSWORD_RESET_REQUEST,
    EMAIL_TEMPLATE_NAME_PASSWORD_CHANGED_SUCCESS,
];

pub fn normalize_template_name(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        .collect::<String>()
        .replace('_', "-")
        .to_lowercase()
}

pub fn is_supported_template_name(name: &str) -> bool {
    SUPPORTED_EMAIL_TEMPLATE_NAMES.contains(&name)
}

pub fn template_trigger_endpoints(name: &str) -> Option<Vec<&'static str>> {
    match name {
        EMAIL_TEMPLATE_NAME_EMAIL_OTP => {
            Some(vec!["/v1/auth/register", "/v1/auth/verify-email/request"])
        }
        EMAIL_TEMPLATE_NAME_WELCOME => Some(vec!["/v1/auth/verify-email/confirm"]),
        EMAIL_TEMPLATE_NAME_PASSWORD_RESET_REQUEST => {
            Some(vec!["/v1/auth/password/forgot/request"])
        }
        EMAIL_TEMPLATE_NAME_PASSWORD_CHANGED_SUCCESS => {
            Some(vec!["/v1/auth/password/reset", "/v1/auth/password/change"])
        }
        _ => None,
    }
}

pub fn template_description(name: &str) -> Option<&'static str> {
    match name {
        EMAIL_TEMPLATE_NAME_EMAIL_OTP => {
            Some("Email OTP sent during registration and verify-email requests.")
        }
        EMAIL_TEMPLATE_NAME_WELCOME => {
            Some("Welcome email sent after successful email verification.")
        }
        EMAIL_TEMPLATE_NAME_PASSWORD_RESET_REQUEST => {
            Some("Password reset OTP email sent when forgot-password is requested.")
        }
        EMAIL_TEMPLATE_NAME_PASSWORD_CHANGED_SUCCESS => {
            Some("Password changed confirmation email sent after successful reset/change.")
        }
        _ => None,
    }
}

pub fn normalize_and_validate_template_name(raw: &str) -> Result<String, String> {
    let name = normalize_template_name(raw);
    if name.is_empty() {
        return Err("template name is required".to_string());
    }
    if !is_supported_template_name(&name) {
        return Err(format!(
            "unsupported template name '{name}', supported: {}",
            SUPPORTED_EMAIL_TEMPLATE_NAMES.join(", ")
        ));
    }
    Ok(name)
}

pub fn sanitize_subject_template(raw: &str) -> Result<String, String> {
    let subject = raw.trim();
    if subject.is_empty() {
        return Err("subject_template is required".to_string());
    }
    if subject.len() > MAX_SUBJECT_LEN {
        return Err(format!(
            "subject_template must be <= {MAX_SUBJECT_LEN} characters"
        ));
    }
    if subject.contains('\n') || subject.contains('\r') {
        return Err("subject_template cannot contain newlines".to_string());
    }
    Ok(subject.to_string())
}

pub fn sanitize_html_template(raw: &str) -> Result<String, String> {
    let html = raw.trim();
    if html.is_empty() {
        return Err("html_template is required".to_string());
    }
    if html.len() > MAX_HTML_LEN {
        return Err(format!(
            "html_template must be <= {MAX_HTML_LEN} characters"
        ));
    }

    let sanitized = ammonia::clean(html);
    if sanitized.trim().is_empty() {
        return Err("html_template is empty after sanitization".to_string());
    }

    Ok(sanitized)
}

pub fn is_valid_placeholder_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn validate_variables(variables: &HashMap<String, String>) -> Result<(), String> {
    if variables.len() > MAX_VARIABLES {
        return Err(format!("too many template variables, max={MAX_VARIABLES}"));
    }
    for (key, value) in variables {
        if !is_valid_placeholder_key(key) {
            return Err(format!("invalid variable key `{key}`"));
        }
        if value.len() > MAX_VARIABLE_VALUE_LEN {
            return Err(format!("variable `{key}` exceeds max length"));
        }
    }
    Ok(())
}

pub fn collect_placeholders(subject_template: &str, html_template: &str) -> Vec<String> {
    let mut placeholders = BTreeSet::new();
    extract_placeholders(subject_template, &mut placeholders);
    extract_placeholders(html_template, &mut placeholders);
    placeholders.into_iter().collect()
}

pub fn render_subject(
    subject_template: &str,
    variables: &HashMap<String, String>,
) -> Result<String, String> {
    let rendered = render_template(subject_template, variables, false)?;
    sanitize_subject_template(&rendered)
}

pub fn render_html(
    html_template: &str,
    variables: &HashMap<String, String>,
) -> Result<String, String> {
    let rendered = render_template(html_template, variables, true)?;
    sanitize_html_template(&rendered)
}

fn extract_placeholders(template: &str, out: &mut BTreeSet<String>) {
    let mut cursor = 0;
    while let Some(open_rel) = template[cursor..].find("{{") {
        let open = cursor + open_rel + 2;
        let Some(close_rel) = template[open..].find("}}") else {
            break;
        };
        let close = open + close_rel;
        let key = template[open..close].trim();
        if is_valid_placeholder_key(key) {
            out.insert(key.to_string());
        }
        cursor = close + 2;
    }
}

fn render_template(
    template: &str,
    variables: &HashMap<String, String>,
    escape_values_for_html: bool,
) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut cursor = 0;

    while let Some(open_rel) = template[cursor..].find("{{") {
        let open = cursor + open_rel;
        out.push_str(&template[cursor..open]);

        let token_start = open + 2;
        let Some(close_rel) = template[token_start..].find("}}") else {
            return Err("template contains unclosed placeholder".to_string());
        };
        let token_end = token_start + close_rel;
        let key = template[token_start..token_end].trim();
        if !is_valid_placeholder_key(key) {
            return Err(format!("template contains invalid placeholder `{key}`"));
        }
        let value = variables
            .get(key)
            .ok_or_else(|| format!("missing template variable `{key}`"))?;

        if escape_values_for_html {
            out.push_str(&escape_html(value));
        } else {
            out.push_str(value);
        }

        cursor = token_end + 2;
    }

    out.push_str(&template[cursor..]);
    Ok(out)
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_html_removes_scripts() {
        let sanitized = sanitize_html_template("<p>ok</p><script>alert(1)</script>").unwrap();
        assert!(sanitized.contains("<p>ok</p>"));
        assert!(!sanitized.contains("<script>"));
    }

    #[test]
    fn render_html_escapes_variables() {
        let template = "<p>Hello {{name}}</p>";
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "<b>bob</b>".to_string());

        let rendered = render_html(template, &vars).unwrap();
        assert!(rendered.contains("&lt;b&gt;bob&lt;/b&gt;"));
    }

    #[test]
    fn render_requires_all_variables() {
        let template = "<p>Hello {{name}}</p>";
        let err = render_html(template, &HashMap::new()).unwrap_err();
        assert!(err.contains("missing template variable"));
    }

    #[test]
    fn key_normalization_filters_invalid_chars() {
        let name = normalize_template_name(" Welcome ");
        assert_eq!(name, "welcome");
    }

    #[test]
    fn normalize_template_name_replaces_underscore() {
        let name = normalize_template_name("password_reset_request");
        assert_eq!(name, "password-reset-request");
    }

    #[test]
    fn template_name_is_supported() {
        assert!(is_supported_template_name("welcome"));
    }
}
