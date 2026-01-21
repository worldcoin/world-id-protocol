use ark_ff::{BigInteger as _, PrimeField as _};

/// Computes the message to be signed for the RP signature over the nonce and timestamp.
#[must_use]
pub fn compute_rp_signature_msg(nonce: ark_babyjubjub::Fq, timestamp: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_be());
    msg.extend(timestamp.to_be_bytes());
    msg
}
