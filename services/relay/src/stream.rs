use std::collections::HashSet;
use std::pin::Pin;
use std::time::Duration;

use alloy::{
    primitives::{Address, U160, U256},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Header},
    sol_types::SolEvent,
};
use futures::Stream;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::{bindings::{
    ICredentialSchemaIssuerRegistry, IOprfKeyRegistry, IWorldIDRegistry, IWorldIDSource,
}, cli::args::WorldChainConfig};
use crate::proof::ChainCommitment;

/// A boxed, pinned stream of fallible items.
pub type EventStream<E> = Pin<Box<dyn Stream<Item = eyre::Result<E>> + Send>>;

struct StreamMap<S, F> {
    stream: S,
    f: F,
}

impl<E, _E, S, F> StreamMap<S, F>  where S: Stream<Item = E>, F: Fn(E) -> _E {
    fn new(stream: S, f: F) -> Self {
        Self { stream, f }
    }

    pub fn into_stream(self) -> impl Stream<Item = _E> {
        self.stream.map(self.f)
    }
}



// pub async fn map_stream<P, F, E, _E>(
//     provider: P,
//     f: F,
// ) -> eyre::Result<EventStream<_E>>
// where
//     P: Provider,
//     F: Fn(E) -> EventStream<_E>
// {
//     let sub = provider.subscribe_blocks().await?;
//     let stream = sub.into_stream().map()
//     Ok(f(Box::pin(stream)))
// }
