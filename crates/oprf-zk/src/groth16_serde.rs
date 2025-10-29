use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use serde::{Deserialize, Serialize};

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// The `A` element in `G1`.
    #[serde(rename = "pi_a")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g1")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g1")]
    pub a: ark_bn254::G1Affine,
    /// The `B` element in `G2`.
    #[serde(rename = "pi_b")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g2")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g2")]
    pub b: ark_bn254::G2Affine,
    /// The `C` element in `G1`.
    #[serde(rename = "pi_c")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g1")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g1")]
    pub c: ark_bn254::G1Affine,
}

impl From<Groth16Proof> for ark_groth16::Proof<Bn254> {
    fn from(value: Groth16Proof) -> Self {
        Self {
            a: value.a,
            b: value.b,
            c: value.c,
        }
    }
}

impl From<ark_groth16::Proof<Bn254>> for Groth16Proof {
    fn from(value: ark_groth16::Proof<Bn254>) -> Self {
        Self {
            a: value.a,
            b: value.b,
            c: value.c,
        }
    }
}

/// Represents a verification key in JSON format that was created by circom. Supports de/serialization using [`serde`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Groth16VerificationKey {
    /// The protocol used to generate the proof (always `"groth16"`)
    pub protocol: String,
    /// The curve
    pub curve: String,
    /// The number of public inputs
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    /// The element α of the verification key ∈ G1
    #[serde(rename = "vk_alpha_1")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g1")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g1")]
    pub alpha_1: ark_bn254::G1Affine,
    /// The element β of the verification key ∈ G2
    #[serde(rename = "vk_beta_2")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g2")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g2")]
    pub beta_2: ark_bn254::G2Affine,
    /// The γ of the verification key ∈ G2
    #[serde(rename = "vk_gamma_2")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g2")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g2")]
    pub gamma_2: ark_bn254::G2Affine,
    /// The element δ of the verification key ∈ G2
    #[serde(rename = "vk_delta_2")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g2")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g2")]
    pub delta_2: ark_bn254::G2Affine,
    /// The pairing of α and β of the verification key ∈ Gt
    #[serde(rename = "vk_alphabeta_12")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_gt")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_gt")]
    pub alpha_beta_gt: ark_bn254::Fq12,
    /// Used to bind the public inputs to the proof
    #[serde(rename = "IC")]
    #[serde(serialize_with = "ark_serde_compat::serialize_bn254_g1_sequence")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_bn254_g1_sequence")]
    pub ic: Vec<ark_bn254::G1Affine>,
}

impl From<Groth16VerificationKey> for VerifyingKey<Bn254> {
    fn from(vk: Groth16VerificationKey) -> Self {
        VerifyingKey {
            alpha_g1: vk.alpha_1,
            beta_g2: vk.beta_2,
            gamma_g2: vk.gamma_2,
            delta_g2: vk.delta_2,
            gamma_abc_g1: vk.ic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Groth16Proof, Groth16VerificationKey};

    const PROOF: &str = r#"{"pi_a":["9116723326348226310312399687760458379430965793646629199281973649756047436480","2874270905534102053533448138397225723399614825643556082270186179665334613224","1"],"pi_b":[["13328302993272298376458050653251338379859716533551615072852727463498727372592","12701171633796457182683671489148506476790474186771723028154216779603805469575"],["8082634848749541028482697284805475720753045849064639479971735063238995549772","20245972516592660684651816366736428662226358885768931974840625194221925755315"],["1","0"]],"pi_c":["3011399641379772467981372516841419028913642315726922827824714699429906533335","10895927520860009543604229709848836725831147762816413949621715866949585547965","1"]}"#;

    const VK: &str = r#"{"protocol":"groth16","curve":"bn128","nPublic":1,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["11147726250204240425553718976509533562471607057214060089201410948104319395085","7578930958937280071835180946681941543445736407833773661864416097780323268523"],["19323259608937507818318198715669949863835067101358223126995456700412018945827","7326125747274447110428491691423519622729831393346111572514231778923697550810"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["6819801395408938350212900248749732364821477541620635511814266536599629892365","9092252330033992554755034971584864587974280972948086568597554018278609861372","1"],["17882351432929302592725330552407222299541667716607588771282887857165175611387","18907419617206324833977586007131055763810739835484972981819026406579664278293","1"]]}"#;

    #[test]
    fn test_groth16_proof_serde() {
        let proof: Groth16Proof = serde_json::from_str(PROOF).unwrap();
        let serialized = serde_json::to_string(&proof).unwrap();
        assert_eq!(PROOF, serialized);
    }

    #[test]
    fn test_groth16_verification_key_serde() {
        let vk: Groth16VerificationKey = serde_json::from_str(VK).unwrap();
        let serialized = serde_json::to_string(&vk).unwrap();
        assert_eq!(VK, serialized);
    }
}
