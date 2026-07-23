import { p256 } from "@noble/curves/nist.js";

import type { AssertionWitness, RegisteredPasskey } from "./webauthn";

/**
 * Provenance and review boundary:
 * - P-256 group/field operations use MIT-licensed @noble/curves 2.2.0.
 * - The object shape mirrors this repository's passkey `types.nr` and Rust
 *   `PasskeyOwnershipCircuitInput::into_witness`; it is not a generic ABI shim.
 * - Signed-scalar slices and carry bits are derived from the equalities checked
 *   by `ScalarField::into` and `assert_scalar_matches_bignum`, not copied from
 *   the vendored BigCurve code whose standalone license is unresolved.
 * - Tests pin the P-256 vector from ProveKit commit 98a3471560ed246b92c1397e53094eec624af0f4.
 */

const CLIENT_DATA_JSON_MAX_LEN = 256;
const AUTHENTICATOR_DATA_MAX_LEN = 64;
const PASSKEY_SLOT_COUNT = 7;
const MERKLE_DEPTH = 30;
const P256_LIMBS = 3;
const P256_SCALAR_SLICES = 65;
const LIMB_BITS = 120n;
const LIMB_BASE = 1n << LIMB_BITS;
const LIMB_MASK = LIMB_BASE - 1n;
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

export type P256ScalarWitness = {
  limbs: [string, string, string];
  slices: string[];
  skew: boolean;
  borrowLow: boolean;
  borrowMid: boolean;
};

export type P256SignatureWitness = {
  messageDigest: Uint8Array;
  rPointY: Uint8Array;
  messageLimbs: [string, string, string];
  publicKeyXLimbs: [string, string, string];
  publicKeyYLimbs: [string, string, string];
  signatureRLimbs: [string, string, string];
  signatureSLimbs: [string, string, string];
  rPointYLimbs: [string, string, string];
  sG: P256ScalarWitness;
  sP: P256ScalarWitness;
};

export type PasskeyOwnershipNoirInputs = Record<string, unknown> & {
  root: string;
  challenge: string[];
  rp_id_hash: string[];
  inputs: {
    webauthn: {
      public_key_x: string[];
      public_key_y: string[];
      signature: string[];
      client_data_json: NoirBoundedBytes;
      authenticator_data: NoirBoundedBytes;
      challenge_index: string;
      r_point_y: string[];
      message_limbs: [string, string, string];
      public_key_x_limbs: [string, string, string];
      public_key_y_limbs: [string, string, string];
      signature_r_limbs: [string, string, string];
      signature_s_limbs: [string, string, string];
      r_point_y_limbs: [string, string, string];
      s_g_limbs: [string, string, string];
      s_g_slices: string[];
      s_g_skew: boolean;
      s_g_borrow_low: boolean;
      s_g_borrow_mid: boolean;
      s_p_limbs: [string, string, string];
      s_p_slices: string[];
      s_p_skew: boolean;
      s_p_borrow_low: boolean;
      s_p_borrow_mid: boolean;
    };
    public_key_x_limbs_field: [string, string, string];
    public_key_y_limbs_field: [string, string, string];
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

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) result = (result << 8n) | BigInt(byte);
  return result;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(length * 8)) {
    throw new Error(`integer does not fit in ${length} bytes`);
  }
  const result = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function bytesToNoir(bytes: Uint8Array): string[] {
  return Array.from(bytes, String);
}

function bigintToLimbs(value: bigint): [bigint, bigint, bigint] {
  if (value < 0n || value >= 1n << 256n) throw new Error("P-256 value must fit in 256 bits");
  return [value & LIMB_MASK, (value >> LIMB_BITS) & LIMB_MASK, value >> (2n * LIMB_BITS)];
}

function decimalLimbs(value: bigint): [string, string, string] {
  return bigintToLimbs(value).map(String) as [string, string, string];
}

function boundedBytes(bytes: Uint8Array, maxLength: number, name: string): NoirBoundedBytes {
  if (bytes.length > maxLength) throw new Error(`${name} exceeds the circuit maximum of ${maxLength} bytes`);
  const storage = new Uint8Array(maxLength);
  storage.set(bytes);
  return { storage: bytesToNoir(storage), len: String(bytes.length) };
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", copy.buffer));
}

/**
 * Encodes a scalar in the 65-digit signed radix-16 representation constrained by
 * `ScalarField::into`: value = fold(16, 2 * slice - 15) - skew.
 *
 * This implementation is derived directly from that equality. Each low digit
 * is chosen in [-15, 15], with a carry when needed to keep the next digit odd.
 * It intentionally does not copy the unlicensed vendored BigCurve helper.
 */
export function signedRadix16(value: bigint): { slices: number[]; skew: boolean } {
  if (value < 0n || value >= p256.Point.Fn.ORDER) {
    throw new Error("P-256 scalar must be canonical");
  }

  const skew = (value & 1n) === 0n;
  let remaining = value + (skew ? 1n : 0n);
  const littleEndianSlices: number[] = [];

  for (let index = 0; index < P256_SCALAR_SLICES; index += 1) {
    let digit = Number(remaining & 0xfn);
    let next = (remaining - BigInt(digit)) >> 4n;
    if (index < P256_SCALAR_SLICES - 1 && (next & 1n) === 0n) {
      digit -= 16;
      next += 1n;
    }
    littleEndianSlices.push((digit + 15) / 2);
    remaining = next;
  }

  if (remaining !== 0n || littleEndianSlices.some((slice) => !Number.isInteger(slice) || slice < 0 || slice > 15)) {
    throw new Error("failed to encode P-256 scalar as signed radix-16 slices");
  }

  const slices = littleEndianSlices.reverse();
  let reconstructed = 0n;
  for (const slice of slices) reconstructed = reconstructed * 16n + BigInt(slice * 2 - 15);
  reconstructed -= skew ? 1n : 0n;
  if (reconstructed !== value) throw new Error("signed radix-16 scalar reconstruction failed");

  return { slices, skew };
}

function foldSignedSlices(slices: readonly number[]): bigint {
  return slices.reduce((value, slice) => value * 16n + BigInt(slice * 2 - 15), 0n);
}

/** Derives the two carry bits required by the circuit's three 120-bit limb equations. */
export function scalarWitness(value: bigint): P256ScalarWitness {
  const { slices, skew } = signedRadix16(value);
  const [lowLimb, midLimb, highLimb] = bigintToLimbs(value);
  const high = foldSignedSlices(slices.slice(0, 5));
  const mid = foldSignedSlices(slices.slice(5, 35));
  const low = foldSignedSlices(slices.slice(35, 65));
  const borrowMidValue = high - highLimb;
  const borrowLowValue = mid + borrowMidValue * LIMB_BASE - midLimb;

  if ((borrowMidValue !== 0n && borrowMidValue !== 1n) || (borrowLowValue !== 0n && borrowLowValue !== 1n)) {
    throw new Error("signed radix-16 carry is not boolean");
  }
  if (low + borrowLowValue * LIMB_BASE !== lowLimb + (skew ? 1n : 0n)) {
    throw new Error("signed radix-16 limb equations do not reconstruct the scalar");
  }

  return {
    limbs: [lowLimb.toString(), midLimb.toString(), highLimb.toString()],
    slices: slices.map(String),
    skew,
    borrowLow: borrowLowValue === 1n,
    borrowMid: borrowMidValue === 1n,
  };
}

/**
 * Computes the standard ECDSA verification intermediates with noble-curves
 * (MIT, @noble/curves 2.2.0): u1 = z/s, u2 = r/s, R = u1*G + u2*Q.
 */
export async function deriveP256SignatureWitness(
  publicKeyX: Uint8Array,
  publicKeyY: Uint8Array,
  signature: Uint8Array,
  authenticatorData: Uint8Array,
  clientDataJson: Uint8Array,
): Promise<P256SignatureWitness> {
  assertLength(publicKeyX, 32, "P-256 x coordinate");
  assertLength(publicKeyY, 32, "P-256 y coordinate");
  assertLength(signature, 64, "raw P-256 signature");

  const clientDataHash = await sha256(clientDataJson);
  const messageDigest = await sha256(concatBytes(authenticatorData, clientDataHash));
  return deriveP256VerificationWitness(publicKeyX, publicKeyY, signature, messageDigest);
}

/** Derives the circuit helpers from an already-computed 32-byte ECDSA message digest. */
export function deriveP256VerificationWitness(
  publicKeyX: Uint8Array,
  publicKeyY: Uint8Array,
  signature: Uint8Array,
  messageDigest: Uint8Array,
): P256SignatureWitness {
  assertLength(publicKeyX, 32, "P-256 x coordinate");
  assertLength(publicKeyY, 32, "P-256 y coordinate");
  assertLength(signature, 64, "raw P-256 signature");
  assertLength(messageDigest, 32, "P-256 message digest");
  const x = bytesToBigInt(publicKeyX);
  const y = bytesToBigInt(publicKeyY);
  const r = bytesToBigInt(signature.slice(0, 32));
  const s = bytesToBigInt(signature.slice(32));
  const scalarField = p256.Point.Fn;

  if (!scalarField.isValidNot0(r) || !scalarField.isValidNot0(s)) {
    throw new Error("P-256 signature scalars must be non-zero and canonical");
  }

  const publicPoint = p256.Point.fromAffine({ x, y });
  publicPoint.assertValidity();
  const inverseS = scalarField.inv(s);
  const message = bytesToBigInt(messageDigest);
  const sGValue = scalarField.mul(scalarField.create(message), inverseS);
  const sPValue = scalarField.mul(r, inverseS);
  const multiply = (point: typeof p256.Point.BASE, scalar: bigint) =>
    scalar === 0n ? p256.Point.ZERO : point.multiply(scalar);
  const rPoint = multiply(p256.Point.BASE, sGValue).add(multiply(publicPoint, sPValue));
  if (rPoint.equals(p256.Point.ZERO)) throw new Error("P-256 verification produced the point at infinity");
  const affineR = rPoint.toAffine();

  // The current Noir circuit compares x directly with r, rather than x mod n.
  // The unequal case is standards-valid but vanishingly rare and cannot be
  // represented by the current circuit ABI.
  if (affineR.x !== r) throw new Error("P-256 signature is invalid or unsupported by the circuit's direct R.x check");
  const rPointY = bigIntToBytes(affineR.y, 32);

  return {
    messageDigest,
    rPointY,
    messageLimbs: decimalLimbs(message),
    publicKeyXLimbs: decimalLimbs(x),
    publicKeyYLimbs: decimalLimbs(y),
    signatureRLimbs: decimalLimbs(r),
    signatureSLimbs: decimalLimbs(s),
    rPointYLimbs: decimalLimbs(affineR.y),
    sG: scalarWitness(sGValue),
    sP: scalarWitness(sPValue),
  };
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
export async function buildPasskeyOwnershipNoirInputs(
  passkey: RegisteredPasskey,
  assertion: AssertionWitness,
  registry: PasskeyRegistryWitness,
): Promise<PasskeyOwnershipNoirInputs> {
  assertLength(assertion.challenge, 32, "WebAuthn challenge");
  assertLength(assertion.rpIdHash, 32, "RP ID hash");
  if (registry.slotCommitments.length !== PASSKEY_SLOT_COUNT) {
    throw new Error(`registry witness must contain ${PASSKEY_SLOT_COUNT} slot commitments`);
  }
  if (registry.siblings.length !== MERKLE_DEPTH) {
    throw new Error(`registry witness must contain ${MERKLE_DEPTH} Merkle siblings`);
  }
  if (registry.slotIndex < 0 || registry.slotIndex >= PASSKEY_SLOT_COUNT) {
    throw new Error("passkey slot index is outside the circuit slot set");
  }

  const signatureWitness = await deriveP256SignatureWitness(
    passkey.publicKey.x,
    passkey.publicKey.y,
    assertion.signature,
    assertion.authenticatorData,
    assertion.clientDataJson,
  );
  const xLimbs = signatureWitness.publicKeyXLimbs;
  const yLimbs = signatureWitness.publicKeyYLimbs;

  return {
    root: canonicalField(registry.root, "registry root"),
    challenge: bytesToNoir(assertion.challenge),
    rp_id_hash: bytesToNoir(assertion.rpIdHash),
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
        r_point_y: bytesToNoir(signatureWitness.rPointY),
        message_limbs: signatureWitness.messageLimbs,
        public_key_x_limbs: xLimbs,
        public_key_y_limbs: yLimbs,
        signature_r_limbs: signatureWitness.signatureRLimbs,
        signature_s_limbs: signatureWitness.signatureSLimbs,
        r_point_y_limbs: signatureWitness.rPointYLimbs,
        s_g_limbs: signatureWitness.sG.limbs,
        s_g_slices: signatureWitness.sG.slices,
        s_g_skew: signatureWitness.sG.skew,
        s_g_borrow_low: signatureWitness.sG.borrowLow,
        s_g_borrow_mid: signatureWitness.sG.borrowMid,
        s_p_limbs: signatureWitness.sP.limbs,
        s_p_slices: signatureWitness.sP.slices,
        s_p_skew: signatureWitness.sP.skew,
        s_p_borrow_low: signatureWitness.sP.borrowLow,
        s_p_borrow_mid: signatureWitness.sP.borrowMid,
      },
      // Both key representations are deliberately sourced from the same bytes.
      // The circuit must still constrain their equality as its security boundary.
      public_key_x_limbs_field: [...xLimbs],
      public_key_y_limbs_field: [...yLimbs],
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
