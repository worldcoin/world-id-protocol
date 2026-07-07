//! Configuration types and environment parsing for the OPRF accountant.

use serde::Deserialize;
use taceo_nodes_common::postgres::PostgresConfig;

/// The configuration for the OPRF accountant service.
///
/// It can be configured via environment variables.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct OprfAccountantConfig {
    /// The postgres config
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,
}
