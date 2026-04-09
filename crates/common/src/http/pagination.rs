use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct Pagination {
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CursorPagination {
    pub limit: u32,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CursorPage<T> {
    pub data: Vec<T>,
    pub pagination: CursorPagination,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct OffsetCursor {
    pub offset: usize,
}

pub fn normalize_limit(limit: Option<u32>, default: u32, max: u32) -> u32 {
    match limit.unwrap_or(default) {
        0 => default,
        value => value.min(max),
    }
}

pub fn parse_offset_cursor(cursor: Option<&str>) -> Result<usize, String> {
    let Some(raw_cursor) = cursor else {
        return Ok(0);
    };
    let trimmed = raw_cursor.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }

    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(trimmed) {
        if let Ok(cursor) = serde_json::from_slice::<OffsetCursor>(&decoded) {
            return Ok(cursor.offset);
        }
    }

    trimmed
        .parse::<usize>()
        .map_err(|_| "cursor must be a valid offset cursor".to_string())
}

pub fn encode_offset_cursor(offset: usize) -> Option<String> {
    serde_json::to_vec(&OffsetCursor { offset })
        .ok()
        .map(|value| URL_SAFE_NO_PAD.encode(value))
}
