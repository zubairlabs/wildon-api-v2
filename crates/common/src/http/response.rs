use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiResponse<T>
where
    T: Serialize,
{
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct ApiListResponse<T, M>
where
    T: Serialize,
    M: Serialize,
{
    pub data: T,
    pub pagination: M,
}
