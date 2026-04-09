use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use errors::{DomainError, ErrorEnvelope};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Json<T>(pub T);

#[derive(Debug, Clone)]
pub struct JsonRejection {
    status: StatusCode,
    domain: DomainError,
    message: String,
    request_id: String,
    meta: BTreeMap<String, String>,
}

impl JsonRejection {
    fn new(
        status: StatusCode,
        domain: DomainError,
        message: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            status,
            domain,
            message: message.into(),
            request_id: request_id.into(),
            meta: BTreeMap::new(),
        }
    }

    fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.meta.insert(key.into(), value.into());
        self
    }
}

impl IntoResponse for JsonRejection {
    fn into_response(self) -> Response {
        (
            self.status,
            axum::Json(ErrorEnvelope::new(
                self.domain,
                self.message,
                self.request_id,
                None,
                self.meta,
            )),
        )
            .into_response()
    }
}

#[async_trait]
impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
    Bytes: FromRequest<S>,
{
    type Rejection = JsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let request_id = request_id_from_headers(&parts.headers);

        if !has_json_content_type(&parts.headers) {
            return Err(JsonRejection::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                DomainError::InvalidArgument,
                "content-type must be application/json",
                request_id,
            ));
        }

        let req = Request::from_parts(parts, body);
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| {
                JsonRejection::new(
                    StatusCode::BAD_REQUEST,
                    DomainError::InvalidArgument,
                    "failed to read JSON request body",
                    request_id.clone(),
                )
            })?;

        if bytes.is_empty() {
            return Err(JsonRejection::new(
                StatusCode::BAD_REQUEST,
                DomainError::InvalidArgument,
                "request body must not be empty",
                request_id,
            ));
        }

        deserialize_strict_json(&bytes, request_id).map(Self)
    }
}

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

fn deserialize_strict_json<T>(
    bytes: &[u8],
    request_id: String,
) -> Result<T, JsonRejection>
where
    T: DeserializeOwned,
{
    let mut ignored_paths = Vec::new();
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde_ignored::deserialize(&mut deserializer, |path| {
        ignored_paths.push(path.to_string());
    })
    .map_err(|err| {
        JsonRejection::new(
            StatusCode::BAD_REQUEST,
            DomainError::InvalidArgument,
            format!("invalid JSON body: {err}"),
            request_id.clone(),
        )
    })?;

    deserializer.end().map_err(|err| {
        JsonRejection::new(
            StatusCode::BAD_REQUEST,
            DomainError::InvalidArgument,
            format!("invalid JSON body: {err}"),
            request_id.clone(),
        )
    })?;

    if !ignored_paths.is_empty() {
        return Err(JsonRejection::new(
            StatusCode::BAD_REQUEST,
            DomainError::InvalidArgument,
            "JSON body contains unknown field(s)",
            request_id,
        )
        .with_meta("unknown_fields", ignored_paths.join(",")));
    }

    Ok(value)
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
        .is_some_and(|value| value.starts_with("application/json"))
}

fn request_id_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "missing".to_string())
}
