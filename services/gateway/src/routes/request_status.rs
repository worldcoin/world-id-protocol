use crate::{
    request_tracker::RequestTracker,
    types::{ApiResult, RequestStatusResponse},
    ErrorResponse as ApiError,
};
use axum::{extract::Path, http::StatusCode, response::IntoResponse, Json};

pub(crate) async fn request_status(
    axum::Extension(tracker): axum::Extension<RequestTracker>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let record = tracker
        .snapshot(&id)
        .await
        .ok_or_else(ApiError::not_found)?;

    let body = RequestStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::OK, Json(body)))
}
