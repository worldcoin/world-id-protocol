use testcontainers::{
    ContainerAsync,
    core::{CopyDataSource, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};
use tracing::{info, info_span, Instrument};

const FOUNDRY_IMAGE: &str = "ghcr.io/foundry-rs/foundry";
const FOUNDRY_TAG: &str = "latest";

/// Internal anvil port inside the container.
const ANVIL_PORT: u16 = 8545;

/// Container-internal path where the genesis file is mounted.
const GENESIS_CONTAINER_PATH: &str = "/genesis.json";

/// A running anvil instance backed by a Docker container via testcontainers.
///
/// The container is automatically removed when this value is dropped.
#[allow(dead_code)]
pub struct AnvilContainer {
    /// Human-readable name for this chain (e.g. "wc", "eth").
    pub name: String,
    /// Chain ID configured on the anvil instance.
    pub chain_id: u64,
    /// Host port mapped to the container's anvil port.
    pub host_port: u16,
    /// The underlying testcontainers handle. Kept alive to prevent early cleanup.
    _container: ContainerAsync<GenericImage>,
}

impl AnvilContainer {
    /// Start a new anvil container with the given name and chain ID.
    ///
    /// When `genesis` is `Some`, the raw JSON bytes are copied into the
    /// container and anvil is launched with `--init /genesis.json` so that the
    /// chain starts with pre-loaded accounts, bytecode, and storage.
    ///
    /// The container uses the official Foundry Docker image and exposes anvil
    /// on a random host port. The returned [`AnvilContainer`] keeps the Docker
    /// container alive until it is dropped.
    pub async fn start(
        name: &str,
        chain_id: u64,
        genesis: Option<&[u8]>,
    ) -> eyre::Result<Self> {
        let span = info_span!("anvil", name, chain_id);

        async {
            info!("starting anvil container");

            let chain_id_str = chain_id.to_string();
            let mut cmd_args = vec!["--host", "0.0.0.0", "--chain-id", &chain_id_str];

            if genesis.is_some() {
                cmd_args.extend(["--init", GENESIS_CONTAINER_PATH]);
            }

            let image = GenericImage::new(FOUNDRY_IMAGE, FOUNDRY_TAG)
                .with_exposed_port(ANVIL_PORT.tcp())
                .with_wait_for(WaitFor::message_on_stdout("Listening on"))
                .with_entrypoint("anvil")
                .with_cmd(cmd_args);

            // If a genesis file is provided, copy it into the container.
            let image = if let Some(data) = genesis {
                info!(bytes = data.len(), "injecting genesis alloc into container");
                image.with_copy_to(
                    GENESIS_CONTAINER_PATH,
                    CopyDataSource::Data(data.to_vec()),
                )
            } else {
                image
            };

            let container = image
                .start()
                .await
                .map_err(|e| eyre::eyre!("failed to start anvil container '{name}': {e}"))?;

            let host_port = container
                .get_host_port_ipv4(ANVIL_PORT.tcp())
                .await
                .map_err(|e| eyre::eyre!("failed to get host port for anvil '{name}': {e}"))?;

            info!(host_port, "anvil container ready");

            Ok(Self {
                name: name.to_string(),
                chain_id,
                host_port,
                _container: container,
            })
        }
        .instrument(span)
        .await
    }

    /// Returns the HTTP JSON-RPC URL for this anvil instance.
    pub fn rpc_url(&self) -> String {
        format!("http://localhost:{}", self.host_port)
    }
}

