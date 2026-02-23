use alloy_primitives::Bytes;

pub trait Relayer {
    fn send_message(&self, payload: Bytes, attributes: Bytes) -> eyre::Result<()>;
}
