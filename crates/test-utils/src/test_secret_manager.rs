use std::{collections::HashSet, str::FromStr, sync::Arc};

use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use oprf_core::ddlog_equality::shamir::DLogShareShamir;
use oprf_service::{
    oprf_key_material_store::OprfKeyMaterialStore,
    secret_manager::{SecretManager, StoreDLogShare},
};
use oprf_types::{OprfKeyId, ShareEpoch};
use parking_lot::Mutex;

#[derive(Clone)]
pub struct TestSecretManager {
    wallet_private_key: PrivateKeySigner,
    store: Arc<Mutex<HashSet<OprfKeyId>>>,
}

impl TestSecretManager {
    pub fn new(wallet_private_key: &str) -> Self {
        Self {
            wallet_private_key: PrivateKeySigner::from_str(wallet_private_key)
                .expect("valid private key"),
            store: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn load_rps(&self) -> Vec<OprfKeyId> {
        self.store.lock().iter().copied().collect()
    }
}

#[async_trait]
impl SecretManager for TestSecretManager {
    async fn load_or_insert_wallet_private_key(&self) -> eyre::Result<PrivateKeySigner> {
        Ok(self.wallet_private_key.clone())
    }

    async fn load_secrets(&self) -> eyre::Result<OprfKeyMaterialStore> {
        Ok(OprfKeyMaterialStore::default())
    }

    async fn store_dlog_share(&self, store: StoreDLogShare) -> eyre::Result<()> {
        let StoreDLogShare {
            oprf_key_id,
            oprf_public_key: _,
            share: _,
        } = store;
        self.store.lock().insert(oprf_key_id);
        Ok(())
    }

    async fn remove_dlog_share(&self, rp_id: OprfKeyId) -> eyre::Result<()> {
        if !self.store.lock().remove(&rp_id) {
            panic!("trying to remove rp id that does not exist");
        }
        Ok(())
    }

    async fn update_dlog_share(
        &self,
        _: OprfKeyId,
        _: ShareEpoch,
        _: DLogShareShamir,
    ) -> eyre::Result<()> {
        unreachable!()
    }
}

pub fn create_secret_managers(node_private_keys: &[PrivateKeySigner; 3]) -> [TestSecretManager; 3] {
    [
        TestSecretManager::new(
            &hex::encode(node_private_keys[0].credential().to_bytes()),
            // "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
        ),
        TestSecretManager::new(
            &hex::encode(node_private_keys[1].credential().to_bytes()),
            // "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
        ),
        TestSecretManager::new(
            &hex::encode(node_private_keys[2].credential().to_bytes()),
            // "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
        ),
    ]
}
