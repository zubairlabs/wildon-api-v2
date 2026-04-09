use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
use tonic::Code;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    InvalidArgument,
    RateLimited,
    Unavailable,
    Internal,
}

impl DomainError {
    pub fn code_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "ERROR_CODE_UNAUTHORIZED",
            Self::Forbidden => "ERROR_CODE_FORBIDDEN",
            Self::NotFound => "ERROR_CODE_NOT_FOUND",
            Self::Conflict => "ERROR_CODE_CONFLICT",
            Self::InvalidArgument => "ERROR_CODE_INVALID_ARGUMENT",
            Self::RateLimited => "ERROR_CODE_RATE_LIMITED",
            Self::Unavailable => "ERROR_CODE_UNAVAILABLE",
            Self::Internal => "ERROR_CODE_INTERNAL",
        }
    }

    pub fn grpc_code(self) -> Code {
        match self {
            Self::Unauthorized => Code::Unauthenticated,
            Self::Forbidden => Code::PermissionDenied,
            Self::NotFound => Code::NotFound,
            Self::Conflict => Code::AlreadyExists,
            Self::InvalidArgument => Code::InvalidArgument,
            Self::RateLimited => Code::ResourceExhausted,
            Self::Unavailable => Code::Unavailable,
            Self::Internal => Code::Internal,
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::InvalidArgument => 400,
            Self::RateLimited => 429,
            Self::Unavailable => 503,
            Self::Internal => 500,
        }
    }
}

impl From<Code> for DomainError {
    fn from(code: Code) -> Self {
        match code {
            Code::Unauthenticated => Self::Unauthorized,
            Code::PermissionDenied => Self::Forbidden,
            Code::NotFound => Self::NotFound,
            Code::AlreadyExists | Code::FailedPrecondition | Code::Aborted => Self::Conflict,
            Code::InvalidArgument | Code::OutOfRange => Self::InvalidArgument,
            Code::ResourceExhausted => Self::RateLimited,
            Code::Unavailable | Code::DeadlineExceeded => Self::Unavailable,
            _ => Self::Internal,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

impl ErrorEnvelope {
    pub fn new(
        domain: DomainError,
        message: impl Into<String>,
        request_id: impl Into<String>,
        trace_id: Option<String>,
        meta: BTreeMap<String, String>,
    ) -> Self {
        Self {
            error: ErrorBody {
                code: domain.code_str().to_string(),
                message: message.into(),
                request_id: request_id.into(),
                trace_id,
                meta,
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("internal error")]
    Internal,
}
