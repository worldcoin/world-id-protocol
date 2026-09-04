import type { AssertionWitness, RegisteredPasskey } from "./webauthn";

const CLIENT_DATA_JSON_MAX_LEN = 256;
const AUTHENTICATOR_DATA_MAX_LEN = 64;
const PASSKEY_SLOT_COUNT = 7;
const MERKLE_DEPTH = 30;
const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export type PasskeyRegistryWitness = {
  leafIndex: number;
  root: string;
  slotIndex: number;
  slotCommitments: string[];
  siblings: string[];
};

export type NoirBoundedBytes = {
  storage: string[];
  len: string;
};

export type PasskeyOwnershipNoirInputs = Record<string, unknown> & {
  root: string;
  challenge: string[];
  rp_id_hash: string[];
  nonce: string[];
  inputs: {
    webauthn: {
      public_key_x: string[];
      public_key_y: string[];
      signature: string[];
      client_data_json: NoirBoundedBytes;
      authenticator_data: NoirBoundedBytes;
      challenge_index: string;
    };
    slot_commitments: string[];
    passkey_slot_index: string;
    merkle_proof: {
      leaf_index: string;
      siblings: string[];
    };
  };
};

function assertLength(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) throw new Error(`${name} must contain exactly ${length} bytes`);
}

function bytesToNoir(bytes: Uint8Array): string[] {
  return Array.from(bytes, String);
}

function boundedBytes(bytes: Uint8Array, maxLength: number, name: string): NoirBoundedBytes {
  if (bytes.length > maxLength) throw new Error(`${name} exceeds the circuit maximum of ${maxLength} bytes`);
  const storage = new Uint8Array(maxLength);
  storage.set(bytes);
  return { storage: bytesToNoir(storage), len: String(bytes.length) };
}

function canonicalField(value: string, name: string): string {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${name} must be a canonical decimal field string`);
  const numeric = BigInt(value);
  if (numeric >= BN254_SCALAR_MODULUS) throw new Error(`${name} is outside the BN254 scalar field`);
  return value;
}

function uint32(value: number, name: string): string {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(`${name} must be a u32`);
  }
  return String(value);
}

/** Builds the exact nested input object consumed by `passkey_ownership_proof::main`. */
export function buildPasskeyOwnershipNoirInputs(
  passkey: RegisteredPasskey,
  assertion: AssertionWitness,
  registry: PasskeyRegistryWitness,
  nonce: Uint8Array,
): PasskeyOwnershipNoirInputs {
  assertLength(passkey.publicKey.x, 32, "P-256 x coordinate");
  assertLength(passkey.publicKey.y, 32, "P-256 y coordinate");
  assertLength(assertion.signature, 64, "raw P-256 signature");
  assertLength(assertion.challenge, 32, "WebAuthn challenge");
  assertLength(assertion.rpIdHash, 32, "RP ID hash");
  assertLength(nonce, 32, "proof request nonce");
  if (registry.slotCommitments.length !== PASSKEY_SLOT_COUNT) {
    throw new Error(`registry witness must contain ${PASSKEY_SLOT_COUNT} slot commitments`);
  }
  if (registry.siblings.length !== MERKLE_DEPTH) {
    throw new Error(`registry witness must contain ${MERKLE_DEPTH} Merkle siblings`);
  }
  if (registry.slotIndex < 0 || registry.slotIndex >= PASSKEY_SLOT_COUNT) {
    throw new Error("passkey slot index is outside the circuit slot set");
  }

  return {
    root: canonicalField(registry.root, "registry root"),
    challenge: bytesToNoir(assertion.challenge),
    rp_id_hash: bytesToNoir(assertion.rpIdHash),
    nonce: bytesToNoir(nonce),
    inputs: {
      webauthn: {
        public_key_x: bytesToNoir(passkey.publicKey.x),
        public_key_y: bytesToNoir(passkey.publicKey.y),
        signature: bytesToNoir(assertion.signature),
        client_data_json: boundedBytes(assertion.clientDataJson, CLIENT_DATA_JSON_MAX_LEN, "clientDataJSON"),
        authenticator_data: boundedBytes(
          assertion.authenticatorData,
          AUTHENTICATOR_DATA_MAX_LEN,
          "authenticatorData",
        ),
        challenge_index: uint32(assertion.challengeIndex, "challenge index"),
      },
      slot_commitments: registry.slotCommitments.map((value, index) =>
        canonicalField(value, `slot commitment ${index}`),
      ),
      passkey_slot_index: uint32(registry.slotIndex, "passkey slot index"),
      merkle_proof: {
        leaf_index: uint32(registry.leafIndex, "Merkle leaf index"),
        siblings: registry.siblings.map((value, index) => canonicalField(value, `Merkle sibling ${index}`)),
      },
    },
  };
}
