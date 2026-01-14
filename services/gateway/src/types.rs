use crate::{
    create_batcher::CreateBatcherHandle,
    ops_batcher::OpsBatcherHandle,
    request_tracker::{RequestKind, RequestState},
    ErrorResponse as ApiError,
};
use alloy::{primitives::Address, providers::DynProvider};
use serde::Serialize;
use utoipa::ToSchema;

/// Maximum number of authenticators per account (matches contract default).
pub(crate) const MAX_AUTHENTICATORS: u32 = 7;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) registry_addr: Address,
    pub(crate) provider: DynProvider,
    pub(crate) batcher: CreateBatcherHandle,
    pub(crate) ops_batcher: OpsBatcherHandle,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RequestStatusResponse {
    pub(crate) request_id: String,
    pub(crate) kind: RequestKind,
    pub(crate) status: RequestState,
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;
