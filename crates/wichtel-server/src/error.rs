//! API errors: HTTP status + `{"error": "<code>", "message": "…"}` (docs/api.md).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use wichtel_api::{ErrorCode, ErrorResponse};

use crate::store::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: &'static str,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
    pub const fn bad_request(message: &'static str) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }
    pub const fn unauthorized() -> Self {
        Self::new(ErrorCode::Unauthorized, "missing or invalid credentials")
    }
    pub const fn not_found() -> Self {
        Self::new(ErrorCode::NotFound, "not found")
    }
    pub const fn conflict(message: &'static str) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
    pub const fn internal() -> Self {
        Self::new(ErrorCode::Internal, "internal error")
    }

    pub fn status(&self) -> StatusCode {
        match self.code {
            ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Conflict | ErrorCode::GroupFull | ErrorCode::TooFewParticipants => {
                StatusCode::CONFLICT
            }
            ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        tracing::error!(error = %e, "store error");
        Self::internal()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorResponse {
            error: self.code,
            message: self.message.to_owned(),
        };
        (self.status(), Json(body)).into_response()
    }
}
