//! Solana-oriented verifier adapter for the World ID Groth16 verifier.
//!
//! The verifier itself is delegated to `groth16-solana`, which uses Solana's
//! BN254 syscall wrappers. This crate only bridges World ID's current Solidity
//! verifier constants and compressed proof layout into that library.

use std::str::FromStr;

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    errors::Groth16Error,
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use num_bigint::BigUint;
use solana_bn254::prelude::alt_bn128_multiplication;

const BN254_SCALAR_FIELD_MINUS_ONE_HEX: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
const BN254_BASE_FIELD_HEX: &str =
    "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

const ALPHA_X: &str =
    "16428432848801857252194528405604668803277877773566238944394625302971855135431";
const ALPHA_Y: &str =
    "16846502678714586896801519656441059708016666274385668027902869494772365009666";

const BETA_X_0: &str =
    "16348171800823588416173124589066524623406261996681292662100840445103873053252";
const BETA_X_1: &str =
    "3182164110458002340215786955198810119980427837186618912744689678939861918171";
const BETA_NEG_Y_0: &str =
    "2201110634874208316029461379665464214311652449122716859599404043531197932830";
const BETA_NEG_Y_1: &str =
    "16967440155991088963264821016081390709021985423659024754853266501192363523869";

const GAMMA_X_0: &str =
    "10857046999023057135944570762232829481370756359578518086990519993285655852781";
const GAMMA_X_1: &str =
    "11559732032986387107991004021392285783925812861821192530917403151452391805634";
const GAMMA_NEG_Y_0: &str =
    "13392588948715843804641432497768002650278120570034223513918757245338268106653";
const GAMMA_NEG_Y_1: &str =
    "17805874995975841540914202342111839520379459829704422454583296818431106115052";

const DELTA_X_0: &str =
    "6198252822679132168335183900719774479358254696910202838593113610721221509433";
const DELTA_X_1: &str =
    "18276312260462464301786116071270072837639658096470751911770498446911342110155";
const DELTA_NEG_Y_0: &str =
    "10167911074507550015881959188681566491139541448874422947882119027151601744121";
const DELTA_NEG_Y_1: &str =
    "961355459261578964454916268259895041286114723611312853904195952719979795544";

const IC: [(&str, &str); 16] = [
    (
        "12707154156956426876205421069762951430587922082374452196061203590996603122898",
        "11988051227811702937081487499189950268834685612677837953086727928714085898782",
    ),
    (
        "18130866512109999048944103382025396564839971558080553194336478570622460551663",
        "10917889356338454322413369923730513779104527783498250513211494202730669497355",
    ),
    (
        "10731668278765206671822666331775393605226701497875783152744053599673737484563",
        "606130650215070645556372737058097563845461830266664204296380386472851271064",
    ),
    (
        "7891367436548121483737548370166014724156933560245880131217604852723541599039",
        "4157478755686502527805879927904580889637436179713881901010787535484528032972",
    ),
    (
        "3373978306004882156286995429766013266564958098405135677231188293347044763032",
        "12962051492588420352880494754147536539495746711369409596561829631910232084060",
    ),
    (
        "2200268951285539566855820779868880112679290606319451528102121918046079234595",
        "8476116822948355055307802895990098305123783126262533306459408650921472681502",
    ),
    (
        "555844460264497701134478875915156216851837708786555089341214244707737387913",
        "2353302559916998643178355210712781061605437038299270001070341375677348625332",
    ),
    (
        "10501997153579162514954308445252704336227962138111416309604124217697291910798",
        "18044988622213670783915153901298923726240404002617862955375682341418427866538",
    ),
    (
        "1888455001806267340733075626004133723546503504091872787113656311144830289310",
        "406996656128495100166576166339621844969673303503310199152117374926616505110",
    ),
    (
        "17340575978191110770479268143212865737348453019776150783384376185309886147471",
        "17506278945400349149075539600742500193555940659491693707958852985198491614023",
    ),
    (
        "10294885580137833426781046193094363086413561961612707928134642858760302829012",
        "540605552482323047416300231228748773541700721077534860535925077248936701640",
    ),
    (
        "14097714348605682268199408610137506759608790215454573329754584077607550463296",
        "14314209957942027099186218356215985969619921120822449148608808720036104884978",
    ),
    (
        "13861794529879157596599909112149632156774118530563570014217711280554564353962",
        "10923687406641654062634317199809722315729907668489021389943203237216572875799",
    ),
    (
        "11063492112917510642498508742534757036275498930337887964520624700772755763611",
        "1080275527637065076606546806103721847770274707050820832707341448196359219159",
    ),
    (
        "8305096101809936022610499570545191179240488941163083615993088787122916816091",
        "4051893384402757580214249940740969478380163418551517204511272447676198016741",
    ),
    (
        "15050022005068262203482113579861697100287411162150564670762660051133717708560",
        "12211338396471543847598704140623873930396235403465327507870621016558207727031",
    ),
];

/// Errors returned by the Solana verifier adapter.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Decimal or hexadecimal constant parsing failed.
    #[error("invalid integer encoding")]
    InvalidInteger,
    /// A point could not be decompressed by the Solana BN254 decompression wrapper.
    #[error("failed to decompress proof point")]
    Decompression,
    /// The Solana Groth16 verifier rejected the proof.
    #[error("proof verification failed: {0}")]
    Groth16(#[from] Groth16Error),
    /// A Solana BN254 group operation failed.
    #[error("solana bn254 operation failed")]
    Bn254Operation,
}

/// Verifies a proof that has already been converted to Solana's uncompressed
/// Groth16 input layout.
pub fn verify_uncompressed_proof(
    proof_a_neg: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    public_inputs: &[[u8; 32]; 15],
) -> Result<(), Error> {
    verify_uncompressed_proof_with_vk_sign(proof_a_neg, proof_b, proof_c, public_inputs, false)
}

fn verify_uncompressed_proof_with_vk_sign(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    public_inputs: &[[u8; 32]; 15],
    use_negative_g2_vk: bool,
) -> Result<(), Error> {
    let ic = world_id_ic()?;
    let verifying_key = Groth16Verifyingkey {
        nr_pubinputs: 15,
        vk_alpha_g1: g1(ALPHA_X, ALPHA_Y)?,
        vk_beta_g2: signed_g2(
            BETA_X_0,
            BETA_X_1,
            BETA_NEG_Y_0,
            BETA_NEG_Y_1,
            use_negative_g2_vk,
        )?,
        vk_gamme_g2: signed_g2(
            GAMMA_X_0,
            GAMMA_X_1,
            GAMMA_NEG_Y_0,
            GAMMA_NEG_Y_1,
            use_negative_g2_vk,
        )?,
        vk_delta_g2: signed_g2(
            DELTA_X_0,
            DELTA_X_1,
            DELTA_NEG_Y_0,
            DELTA_NEG_Y_1,
            use_negative_g2_vk,
        )?,
        vk_ic: &ic,
    };

    let mut verifier =
        Groth16Verifier::new(proof_a, proof_b, proof_c, public_inputs, &verifying_key)?;

    verifier.verify().map_err(Error::from)
}

/// Verifies the current Solidity-friendly compressed proof layout.
///
/// This is a compatibility adapter for Phase 0. It converts Solidity's packed
/// low-bit point representation into Solana/ark compressed points, delegates
/// decompression to `groth16-solana`, then delegates verification to the same
/// Solana verifier path as [`verify_uncompressed_proof`].
pub fn verify_solidity_compressed_proof(
    compressed_proof: &[[u8; 32]; 4],
    public_inputs: &[[u8; 32]; 15],
) -> Result<(), Error> {
    let mut last_error = Error::Decompression;

    for a_negative in [false, true] {
        for b_negative in [false, true] {
            for c_negative in [false, true] {
                for g2_x1_first in [false, true] {
                    for negate_a in [false, true] {
                        for use_negative_g2_vk in [false, true] {
                            let Ok(proof_a) =
                                decompress_solidity_g1(&compressed_proof[0], a_negative)
                            else {
                                continue;
                            };
                            let Ok(proof_b) = decompress_solidity_g2(
                                &compressed_proof[2],
                                &compressed_proof[1],
                                b_negative,
                                g2_x1_first,
                            ) else {
                                continue;
                            };
                            let Ok(proof_c) =
                                decompress_solidity_g1(&compressed_proof[3], c_negative)
                            else {
                                continue;
                            };
                            let proof_a_for_pairing = if negate_a {
                                let Ok(proof_a_neg) = negate_g1(&proof_a) else {
                                    continue;
                                };
                                proof_a_neg
                            } else {
                                proof_a
                            };

                            match verify_uncompressed_proof_with_vk_sign(
                                &proof_a_for_pairing,
                                &proof_b,
                                &proof_c,
                                public_inputs,
                                use_negative_g2_vk,
                            ) {
                                Ok(()) => return Ok(()),
                                Err(error) => last_error = error,
                            }
                        }
                    }
                }
            }
        }
    }

    Err(last_error)
}

/// Converts a 32-byte hexadecimal string into a big-endian field element.
pub fn hex_word(value: &str) -> Result<[u8; 32], Error> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let padded;
    let value = if value.len() % 2 == 0 {
        value
    } else {
        padded = format!("0{value}");
        &padded
    };
    let mut bytes = hex::decode(value).map_err(|_| Error::InvalidInteger)?;
    if bytes.len() > 32 {
        return Err(Error::InvalidInteger);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    bytes.fill(0);
    Ok(out)
}

fn world_id_ic() -> Result<[[u8; 64]; 16], Error> {
    let mut ic = [[0u8; 64]; 16];
    for (i, (x, y)) in IC.iter().enumerate() {
        ic[i] = g1(x, y)?;
    }
    Ok(ic)
}

fn g1(x: &str, y: &str) -> Result<[u8; 64], Error> {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&decimal_word(x)?);
    out[32..].copy_from_slice(&decimal_word(y)?);
    Ok(out)
}

fn signed_g2(
    x0: &str,
    x1: &str,
    neg_y0: &str,
    neg_y1: &str,
    use_negative: bool,
) -> Result<[u8; 128], Error> {
    let y0 = if use_negative {
        decimal_biguint(neg_y0)?
    } else {
        positive_from_negative_fp(neg_y0)?
    };
    let y1 = if use_negative {
        decimal_biguint(neg_y1)?
    } else {
        positive_from_negative_fp(neg_y1)?
    };

    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&decimal_word(x1)?);
    out[32..64].copy_from_slice(&decimal_word(x0)?);
    out[64..96].copy_from_slice(&biguint_word(&y1));
    out[96..].copy_from_slice(&biguint_word(&y0));
    Ok(out)
}

fn decompress_solidity_g1(word: &[u8; 32], y_negative: bool) -> Result<[u8; 64], Error> {
    let c = BigUint::from_bytes_be(word);
    let x = c >> 1usize;
    let mut compressed = biguint_word(&x);
    if y_negative {
        compressed[0] |= 0x80;
    }
    decompress_g1(&compressed).map_err(|_| Error::Decompression)
}

fn decompress_solidity_g2(
    c0_word: &[u8; 32],
    c1_word: &[u8; 32],
    y_negative: bool,
    x1_first: bool,
) -> Result<[u8; 128], Error> {
    let c0 = BigUint::from_bytes_be(c0_word);
    let x0 = c0 >> 2usize;

    let mut compressed = [0u8; 64];
    if x1_first {
        compressed[..32].copy_from_slice(c1_word);
        compressed[32..].copy_from_slice(&biguint_word(&x0));
    } else {
        compressed[..32].copy_from_slice(&biguint_word(&x0));
        compressed[32..].copy_from_slice(c1_word);
    }
    if y_negative {
        compressed[0] |= 0x80;
    }

    decompress_g2(&compressed).map_err(|_| Error::Decompression)
}

fn negate_g1(point: &[u8; 64]) -> Result<[u8; 64], Error> {
    let scalar = hex_word(BN254_SCALAR_FIELD_MINUS_ONE_HEX)?;
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(&scalar);

    alt_bn128_multiplication(&input)
        .map_err(|_| Error::Bn254Operation)?
        .try_into()
        .map_err(|_| Error::Bn254Operation)
}

fn positive_from_negative_fp(value: &str) -> Result<BigUint, Error> {
    let p =
        BigUint::parse_bytes(BN254_BASE_FIELD_HEX.as_bytes(), 16).ok_or(Error::InvalidInteger)?;
    let value = decimal_biguint(value)?;
    if value == BigUint::from(0u8) {
        Ok(value)
    } else {
        Ok(p - value)
    }
}

fn decimal_word(value: &str) -> Result<[u8; 32], Error> {
    decimal_biguint(value).map(|value| biguint_word(&value))
}

fn decimal_biguint(value: &str) -> Result<BigUint, Error> {
    BigUint::from_str(value).map_err(|_| Error::InvalidInteger)
}

fn biguint_word(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PROOF: [&str; 4] = [
        "4906f4e17b969ef2cfc44bd96520f01a3f5c32972bca2e10b70e05e03e3d9f13",
        "d6d9a3456e9af7d8f6f78eb3380deb8c93505c062f62fa18b8ef8a2ccb55db8",
        "a92a48edeb327b190048648788de9a8eff0abed5dc93bee8881387da40571278",
        "38f52985c393efb732be8f54b5f00f7f25370ac5945de84e0d8d2f2d298866b8",
    ];

    const SESSION_PROOF: [&str; 4] = [
        "4533f8d38447da676c8eac8ec01ce031af1cc140d8397f3baf792be414c28790",
        "e05c9ada0f2a3ebb5863f0a3412aa852cea67099ce26bb46c44b264af5b6927",
        "178bbfe59fc10b5ec4359ecb21b9f42fb8afef08e90cd3dec903fdd45cddc930",
        "409b8908726ca9151d021fcecc882a3f5e93ba35f6043ad0bd51258b55e5018b",
    ];

    const BROKEN_PROOF: [&str; 4] = [
        "3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8",
        "79a6dee01c030080298a09adfd0294edc84f1650b68763d0aab5d6a1c1bbd8",
        "850d06c33658c9d2cc0e873cb45ad5375a31a6661cd4a11d833466ffe79b8bdd",
        "3282817e430906e0a5f73e22d404971f1e8701d4d4270f3d531f07d0d8819db8",
    ];

    #[test]
    fn verifies_solidity_nullifier_fixture() {
        verify_solidity_compressed_proof(&proof(VALID_PROOF), &nullifier_inputs()).unwrap();
    }

    #[test]
    fn rejects_wrong_rp_id() {
        let mut inputs = nullifier_inputs();
        inputs[8] = hex_word("2").unwrap();

        assert!(verify_solidity_compressed_proof(&proof(VALID_PROOF), &inputs).is_err());
    }

    #[test]
    fn rejects_wrong_credential_issuer() {
        let mut inputs = nullifier_inputs();
        inputs[1] = hex_word("2").unwrap();
        inputs[2] =
            hex_word("1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e").unwrap();
        inputs[3] =
            hex_word("3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3").unwrap();

        assert!(verify_solidity_compressed_proof(&proof(VALID_PROOF), &inputs).is_err());
    }

    #[test]
    fn rejects_broken_nullifier_proof() {
        assert!(
            verify_solidity_compressed_proof(&proof(BROKEN_PROOF), &nullifier_inputs()).is_err()
        );
    }

    #[test]
    fn verifies_solidity_session_fixture() {
        verify_solidity_compressed_proof(&proof(SESSION_PROOF), &session_inputs()).unwrap();
    }

    #[test]
    fn rejects_broken_session_proof() {
        assert!(verify_solidity_compressed_proof(&proof(BROKEN_PROOF), &session_inputs()).is_err());
    }

    fn proof(values: [&str; 4]) -> [[u8; 32]; 4] {
        values.map(|value| hex_word(value).unwrap())
    }

    fn nullifier_inputs() -> [[u8; 32]; 15] {
        inputs(
            "1bae01b23e5f0ee96151331fffb0550351c52e5ee0ced452c762e120723ae702",
            "15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f",
            "0",
        )
    }

    fn session_inputs() -> [[u8; 32]; 15] {
        inputs(
            "1bae01b23e5f0ee96151331fffb0550351c52e5ee0ced452c762e120723ae702",
            "15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f",
            "2025d8e786806a895f7e50ce403f7d6e33e501772b28116908ad6fa5108172f8",
        )
    }

    fn inputs(nullifier: &str, action: &str, session_id: &str) -> [[u8; 32]; 15] {
        [
            hex_word(nullifier).unwrap(),
            hex_word("1").unwrap(),
            hex_word("252c8234509649bb469ecb7a7e758f306b41415f2d80d4d67967902d6f589a81").unwrap(),
            hex_word("230e4f93a5f1187639314dd25e595db06dc18de219cfaeb8cfdf81d4afe910d5").unwrap(),
            hex_word("699cfa47").unwrap(),
            hex_word("0").unwrap(),
            hex_word("af727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853").unwrap(),
            hex_word("1e").unwrap(),
            hex_word("1a6ccf8f70e5de68").unwrap(),
            hex_word(action).unwrap(),
            hex_word("ac79da013272129ddceae6d20c0f579abd04b0a00160ed2be2151bf4014e8d").unwrap(),
            hex_word("187ce5ac507fe0760e95d1893cc6ebf3a115eb9adeaa355c14cc52722a2275be").unwrap(),
            hex_word("1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f").unwrap(),
            hex_word("18e3ab3d5fedc6eaa5e0d06a3a6f3dd5e0bf2d17b18b797a1cc6ff4706169d1e").unwrap(),
            hex_word(session_id).unwrap(),
        ]
    }
}
